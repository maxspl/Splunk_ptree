# Splunk ptree cmd

Alternative to existing versions of splunk process tree. The others didn't work for me since my data source (powershell Get-Process) sometimes causes infinite loops. 

Algorithm stolen here: https://stackoverflow.com/questions/16395207/create-a-process-tree-like-pstree-command-with-python-in-linux


## Installation

Copy ptree repo to your splunk or install .spl file.

## Usage

```
index=* source="processes.csv" 
| ptree child_name=ProcessId parent_name=ParentProcessId CreateTime_name=CreationDate CommandLine_name=CommandLine Process_name=ProcessName CreateTime_name_format="%Y-%m-%d %H:%M:%S.%f"
| table tree
```

## Example
![Alt text](/assets/screenshot.png)

