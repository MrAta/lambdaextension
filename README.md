# An attempt to add BPF programs as an extension for AWS lambda

The provided code sample demonstrates how to get a basic ebpf program extension written in Go up and running.

## Compile package and dependencies

To run this example, you will need to ensure that your build architecture matches that of the Lambda execution environment by compiling with `GOOS=linux` and `GOARCH=amd64` if you are not running in a Linux environment.


```bash
$ make
$ mkdir bin/extensions
$ mv main ebpf_prog bin/extension
```

## Layer Setup Process
The extensions .zip file should contain a root directory called `extensions/`, where the extension executables are located. In this sample project we must include the `go-example-extension` binary.

Creating zip package for the extension:
```bash
$ cd bin
$ zip -r extension.zip extensions/
```

Ensure that you have aws-cli v2 for the commands below.
Publish a new layer using the `extension.zip`. The output of the following command should provide you a layer arn.
```bash
aws lambda publish-layer-version \
 --layer-name "go-example-extension" \
 --region <use your region> \
 --zip-file  "fileb://extension.zip"
```
Note the LayerVersionArn that is produced in the output.
eg. `"LayerVersionArn": "arn:aws:lambda:<region>:123456789012:layer:<layerName>:1"`

Add the newly created layer version to a Lambda function.


## Function Invocation and Extension Execution

To invoke the function (and extension):
```bash
aws lambda invoke \                                                                       
 --function-name <Your function name> \
 --payload <payload in json format> /tmp/invoke-result \
 --cli-binary-format raw-in-base64-out \
 --log-type Tail \
 --region <Your AWS region name>
