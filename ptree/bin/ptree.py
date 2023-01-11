#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals
import sys, collections, os,time
from datetime import datetime
splunkhome = os.environ['SPLUNK_HOME']
sys.path.append(os.path.join(splunkhome, 'etc', 'apps', 'ptree', 'lib'))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

output="PID" + " " * 6 + "Process name" + " " * 25 + "Creation Time" + " " * 20 + "Command Line" +"\n"
output_log=""
@Configuration()
class PtreeCommand(StreamingCommand):
    parent_name = Option(
    doc='''
    **Syntax:** **parent=***<fieldname>*
    **Description:** Name of the field that holds the parent value''',
    require=True, validate=validators.Fieldname())

    child_name = Option(
    doc='''
    **Syntax:** **child=***<fieldname>*
    **Description:** Name of the field that holds the child value''',
    require=True, validate=validators.Fieldname())

    CreateTime_name = Option(
    doc='''
    **Syntax:** **child=***<fieldname>*
    **Description:** Name of the field that holds the child value''',
    require=True, validate=validators.Fieldname())

    CommandLine_name = Option(
    doc='''
    **Syntax:** **child=***<fieldname>*
    **Description:** Name of the field that holds the child value''',
    require=True, validate=validators.Fieldname())

    Process_name = Option(
    doc='''
    **Syntax:** **child=***<fieldname>*
    **Description:** Name of the field that holds the child value''',
    require=True, validate=validators.Fieldname())

    CreateTime_name_format = Option(
    doc='''
    **Syntax:** **child=***<fieldname>*
    **Description:** Name of the field that holds the child value''',
    require=True, validate=None)


    #1. PID_list and PPID_list creation
    def format_input_process_list(self,child_name,parent_name,records):
      global output_log
      global output_log
      #PPID/PID list definition
      PPID_list = []
      PID_list = []
      both_list =[]
      try:
        for record in records:
          if record[parent_name] not in PPID_list:
            PPID_list.append(str(record[parent_name]))
      except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") +"[ERROR] - Failed to PPID/PID list definition. Error :" + str(e)
      try:
        for record in records:
          if record[child_name] not in PID_list:
            PID_list.append(str(record[child_name]))
      except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") +"[ERROR] - Failed to PPID/PID list definition. Error :" + str(e)
      
      both_list.append(PID_list)
      both_list.append(PPID_list)
      return both_list

    #2. Process dict definition : each key is PPID, subkey is a list of child subkeys
    def format_input_process_dict(self,child_name,parent_name,records,PID_list,PPID_list):
      global output_log
      process_dict = {}
      try:
        for i in range(len(PPID_list)):
            key = str(PPID_list[i])
            value=[]
            for record in records:
                if str(key) == record[parent_name]:
                  value.append(str(record[child_name]))
                  # Add the key-value pair to the dictionary
                  process_dict[key] = value
      except Exception as e:
        output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Process dict definition. Error :" + str(e)
      return process_dict

    #3. Process dict list definition
    def format_input_process_dict_list(self,child_name,parent_name,CommandLine_name,CreateTime_name,Process_name,records):
      global output_log
      try:
        process_list_dict = {}
        for record in records:
          key = str(record[child_name])
          values = []
          values.append(record[parent_name])
          values.append(record[CreateTime_name])
          try:
            values.append(record[CommandLine_name])
            output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[INFO] - values.append(record[CommandLine_name]). sucess :"
          except:
            a=1
          try:
            values.append(record[Process_name])
            output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[INFO] - values.append(record[Process_name]). sucess :"
          except Exception as e:
            output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - values.append(record[Process_name]). sucess :" + str(e)
          values[0] = str(values[0])
          process_list_dict[key] = values
      except Exception as e:
        output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Process dict list definition. Error :" + str(e)
      return process_list_dict

    #4. Create rootpid list. Only the tree of theses processes are displayed
    def format_input_rootpid(self,process_list_dict,CreateTime_name_format):
      global output_log
      try:
        root_pid=[]
        for pid in process_list_dict:
          ppid = process_list_dict[pid][0]
          if ppid not in process_list_dict and ppid not in root_pid:
            root_pid.append(pid)
          else:
            if ppid not in root_pid:
              try : 
                CreateTime_pid = datetime.strptime(process_list_dict[pid][1].strip('"'), CreateTime_name_format)
                CreateTime_ppid = datetime.strptime(process_list_dict[ppid][1].strip('"'), CreateTime_name_format)
              except Exception as e:  
                output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Create rootpid list. Error :" + str(e)
              if CreateTime_ppid >=  CreateTime_pid :
                root_pid.append(pid)
      except Exception as e:
        output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Create rootpid list. Error :" + str(e)
      return root_pid

    #5. Build ptree
    def build_ptree(self,parent, tree,process_list_dict,CreateTime_parent, CreateTime_name_format, indent=''):
      global output
      global output_log
      try:
        try :
          CreateTime_parent_mod = datetime.strptime(CreateTime_parent.strip('"'), CreateTime_name_format)
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Build ptree. Error :" + str(e)
        try :
          space = (50 - len(output.split('\n')[-1])) * ' ' 
          space_nb = 45 - len(output.split('\n')[-1]) - len(process_list_dict[parent][3]) - len(str(parent))
          space_nb2 = (space_nb + 25) - len(process_list_dict[parent][1])
          output+=str(parent) + '    ' + process_list_dict[parent][3] + space_nb*' ' + process_list_dict[parent][1] + 10*' ' + process_list_dict[parent][2] + "\n"
        except Exception as e:
          output+=str(parent) + "\n"
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Build ptree. Error :" + str(e)
        if parent not in tree :
          return
        for child in tree[parent][:-1]:
          output+=indent + '|---'
          try:
            CreateTime_child = process_list_dict[child][1]
            CreateTime_child_mod = datetime.strptime(CreateTime_child.strip('"'), CreateTime_name_format)
          except :
            output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Build ptree. Error :" + str(e)
          if CreateTime_parent_mod < CreateTime_child_mod :
            self.build_ptree(child, tree,process_list_dict,CreateTime_child,CreateTime_name_format, indent + '`` ')
        child = tree[parent][-1]
        CreateTime_child = process_list_dict[child][1]
        output+=indent + '`-'
        self.build_ptree(child, tree, process_list_dict,CreateTime_child,CreateTime_name_format,indent + '`` ')
      except Exception as e:
        output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to Build ptree. Error :" + str(e)


    def stream(self, records):
        global output
        global output_log
        record_txt = ''
        records_bak = []
        for record in records:
            record_txt=record
            records_bak.append(record)
            # record['hello']='world'
            # yield record
        #1.PID_list and PPID_list
        try :
          both_list = self.format_input_process_list(self.child_name,self.parent_name,records_bak)
          PID_list=both_list[0]
          PPID_list=both_list[1]
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to create PID_list and PPID_list. Error :" + str(e)
        
        #2.process_dict
        try:
          process_dict = self.format_input_process_dict(self.child_name,self.parent_name,records_bak,PID_list,PPID_list)
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to create process_dict. Error :" + str(e)

        #3. process_list_dict
        try:
          process_dict_list = self.format_input_process_dict_list(self.child_name,self.parent_name,self.CommandLine_name,self.CreateTime_name,self.Process_name,records_bak)
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[INFO] - process_dict_list :" + str(process_dict_list)
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to create process_list_dict. Error :" + str(e)

        #4. rootpid list
        try:
          root_pid = self.format_input_rootpid(process_dict_list,self.CreateTime_name_format)
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to create rootpid list. Error :" + str(e)
                
        #5. build ptree
        try:
          #self.build_ptree(4024,process_dict,process_dict_list,process_dict_list[4024][1])
          a=1
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to print build ptree. Error :" + str(e)

        #6. build full tree
        try:
          for key in process_dict:
            if key != "0":
              output+=""
              if key in root_pid:
                if key in process_dict_list: 
                  self.build_ptree(key,process_dict,process_dict_list,process_dict_list[key][1],self.CreateTime_name_format)
                else : #if the process doesn't exist (only present in PPIDs), assume an old creation time 
                  CreateTime = "1970-01-01 01:01:01"
                  self.build_ptree(key,process_dict,process_dict_list,CreateTime,self.CreateTime_name_format)
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to print build ptree. Error :" + str(e)

        try:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[INFO] - output :" + output
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - Failed to print output. Error :" + str(e)

        try:
          yield {"tree":output}
        except Exception as e:
          output_log+="\n"+time.strftime("[%Y-%m-%d %H:%M:%S %z]") + "[ERROR] - yield. Error :" + str(e)

        try:
          print(output_log,file=open(os.path.join(splunkhome,'etc','apps','ptree','log','output.log'),"w"))
        except Exception as e:
          print("[ERROR] - yield. Error :",e,file=open(os.path.join(splunkhome,'etc','apps','ptree','log','error.log'),"w"))

dispatch(PtreeCommand, sys.argv, sys.stdin, sys.stdout, __name__)


