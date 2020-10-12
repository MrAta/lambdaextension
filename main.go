// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

package main

import (
		"aws-lambda-extensions/go-example-extension/extension"

	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"


	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"strings"
	"sync"

	"github.com/dropbox/goebpf")
var (
	extensionName   = filepath.Base(os.Args[0]) // extension name has to match the filename
	extensionClient = extension.NewClient(os.Getenv("AWS_LAMBDA_RUNTIME_API"))
	printPrefix     = fmt.Sprintf("[%s]", extensionName)

	ErrProgramNotFound = errors.New("program not found")
	ErrMapNotFound     = errors.New("map not found")
)

type Event_t struct {
	KtimeNs uint64
	Pid     uint32
	Uid     uint32
	Gid     uint32
	Type    int32
	Comm    [32]byte
}

type Program struct {
	bpf goebpf.System
	pe  *goebpf.PerfEvents
	wg  sync.WaitGroup
}


func main() {
	ctx, cancel := context.WithCancel(context.Background())

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		s := <-sigs
		cancel()
		println(printPrefix, "Received", s)
		println(printPrefix, "Exiting")
	}()

	res, err := extensionClient.Register(ctx, extensionName)
	if err != nil {
		panic(err)
	}
	println(printPrefix, "Register response:", prettyPrint(res))

	// Will block until shutdown event is received or cancelled via the context.
	processEvents(ctx)
}

func processEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			println(printPrefix, "Waiting for event...")
			res, err := extensionClient.NextEvent(ctx)
			if err != nil {
				println(printPrefix, "Error:", err)
				println(printPrefix, "Exiting")
				return
			}
			println(printPrefix, "Received event:", prettyPrint(res))
			// Exit if we receive a SHUTDOWN event
			if res.EventType == extension.Shutdown {
				println(printPrefix, "Received SHUTDOWN event")
				println(printPrefix, "Exiting")
				return
			} else {
				
				ebpf_main()
			}
		}
	}
}

func prettyPrint(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return ""
	}
	return string(data)
}




func ebpf_main() {

	// cleanup old probes
	if err := goebpf.CleanupProbes(); err != nil {
		log.Println(err)
	}

	// load ebpf program
	p, err := LoadProgram("/opt/extensions/ebpf_prog/kprobe.elf")
	if err != nil {
		log.Fatalf("LoadProgram() failed: %v", err)
	}
	p.ShowInfo()

	// attach ebpf kprobes
	if err := p.AttachProbes(); err != nil {
		log.Fatalf("AttachProbes() failed: %v", err)
	}
	defer p.DetachProbes()

	// wait until Ctrl+C pressed
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	<-ctrlC

	// display some stats
	fmt.Println()
	fmt.Printf("%d Event(s) Received\n", p.pe.EventsReceived)
	fmt.Printf("%d Event(s) lost (e.g. small buffer, delays in processing)\n", p.pe.EventsLost)
}

func LoadProgram(filename string) (*Program, error) {

	// create system
	bpf := goebpf.NewDefaultEbpfSystem()

	// load compiled ebpf elf file
	if err := bpf.LoadElf(filename); err != nil {
		return nil, err
	}

	// load programs
	for _, prog := range bpf.GetPrograms() {
		if err := prog.Load(); err != nil {
			return nil, err
		}
	}

	return &Program{bpf: bpf}, nil
}

func (p *Program) startPerfEvents(events <-chan []byte) {
	p.wg.Add(1)
	go func(events <-chan []byte) {
		defer p.wg.Done()

		// print header
		fmt.Printf("\nTIME          PCOMM             PID    UID    GID    DESC\n\n")
		for {

			// receive exec events
			if b, ok := <-events; ok {

				// parse proc info
				var ev Event_t
				buf := bytes.NewBuffer(b)
				if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
					fmt.Printf("error: %v\n", err)
					continue
				}

				// parse args
				tokens := bytes.Split(buf.Bytes(), []byte{0x00})
				var args []string
				for _, arg := range tokens {
					if len(arg) > 0 {
						args = append(args, string(arg))
					}
				}

				// build display strings
				var desc string
				if len(args) > 0 {
					desc = args[0]
				}
				if len(args) > 2 {
					desc += " " + strings.Join(args[2:], " ")
				}

				// display process execution event
				ts := goebpf.KtimeToTime(ev.KtimeNs)
				fmt.Printf("%s  %-16s  %-6d %-6d %-6d %s\n",
					ts.Format("15:04:05.000"),
					goebpf.NullTerminatedStringToString(ev.Comm[:]),
					ev.Pid, ev.Uid, ev.Gid, desc)

			} else {
				break
			}
		}
	}(events)
}

func (p *Program) stopPerfEvents() {
	p.pe.Stop()
	p.wg.Wait()
}

func (p *Program) AttachProbes() error {

	// attach all probe programs
	for _, prog := range p.bpf.GetPrograms() {
		if err := prog.Attach(nil); err != nil {
			return err
		}
	}

	// get handles to perf event map
	m := p.bpf.GetMapByName("events")
	if m == nil {
		return ErrMapNotFound
	}

	// create perf events
	var err error
	p.pe, err = goebpf.NewPerfEvents(m)
	if err != nil {
		return err
	}
	events, err := p.pe.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		return err
	}

	// start event listeners
	p.wg = sync.WaitGroup{}
	p.startPerfEvents(events)

	return nil
}

func (p *Program) DetachProbes() error {
	p.stopPerfEvents()
	for _, prog := range p.bpf.GetPrograms() {
		prog.Detach()
		prog.Close()
	}
	return nil
}

func (p *Program) ShowInfo() {
	fmt.Println()
	fmt.Println("Maps:")
	for _, item := range p.bpf.GetMaps() {
		m := item.(*goebpf.EbpfMap)
		fmt.Printf("\t%s: %v, Fd %v\n", m.Name, m.Type, m.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range p.bpf.GetPrograms() {
		fmt.Printf("\t%s: %v (%s), size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSection(), prog.GetSize(), prog.GetLicense(),
		)
	}
}
