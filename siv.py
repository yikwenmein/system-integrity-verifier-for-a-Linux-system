
import sys
import hashlib
import argparse
import os
from pathlib import Path
from os.path import join, getsize
import pwd
from pwd import getpwuid
from grp import getgrgid
import time, datetime
import json
import os
i=0
j=0
n=0
m=0
warnings =0
execution_time =0
count = 0
json_file =""
file_info = {}
report_info ={}
verification_report={}
message_digest =""
value = """-----------------------------------------------------------------------------------------------\n
Initialization mode --> siv.py -i -D 'dir' -V 'ver_file' -R 'rep_file' -H 'hash'\n
e.g python siv.py -i -D /home/yikwenmein/Desktop/ass1 -V verification.txt -R report.txt -H sha1\n
-----------------------------------------------------------------------------------------------\n
Verification mode --> siv.py -v -D 'dir' -V 'ver_file' -R 'rep_file'\n
e.g python siv.py -v -D /home/yikwenmein/Desktop/ass1 -V verification.txt -R report.txt\n
-----------------------------------------------------------------------------------------------\n"""

parser = argparse.ArgumentParser(
    description=print(value))
arg_group = parser.add_mutually_exclusive_group()
arg_group.add_argument("-i", "--initialization", action="store_true", help="Initialization mode")
arg_group.add_argument("-v", "--verification", action="store_true", help="Verification mode")
parser.add_argument("-D", "--monitored_directory", type=str, help="Give a Directory that needs to be monitored")
parser.add_argument("-V", "--verification_file", type=str,
                        help="specify a file to store info of files in the directory being monitored.\
                        This verification file should be outside the directory to be monitored")
parser.add_argument("-R", "--report_file", type=str, help="Specify a report file to store ovarall stats of the monitored directory\
                        This report file should be outside the directory to be monitored as well")
parser.add_argument("-H", "--hash_function", type=str, help="Specifies hashing algorithm. Choose either 'SHA-1' or 'MD-5'")
argument = parser.parse_args()

if argument.initialization:
    print("Running in initialization mode\n")
    start_time1 =time.time()
    if os.path.exists(argument.monitored_directory):
        print("Monitored Directory Exist\n")
    else:
        print("Specify a directory for siv to monitor\n")
        sys.exit()

    if os.path.exists(argument.verification_file):
        print("Verification file exist\n")
    else:
        ask =input("No Verification file found.Do you want to create one? yes/no\n")
        if ask=="yes":
            #os.open(argument.report_file, os.O_CREAT, mode=511)
            os.open(argument.verification_file, os.O_CREAT, mode=0o0777)
        else:
            sys.exit()
    if os.path.exists(argument.report_file):
            print("Report file exist\n")
    else:
        ask =input("No report file found.Do you want to create one? yes/no\n")
        if ask=="yes":
            #os.open(argument.report_file, os.O_CREAT, mode=511)
            os.open(argument.report_file, os.O_CREAT, mode=0o0777)
        else:
            sys.exit()
    
    prefix = os.path.commonprefix([argument.verification_file,argument.report_file])
    if prefix==argument.monitored_directory:
        print("Verification and report files should not be inside the monitored_directory\n")
        sys.exit()
    else:
        print("All good.verification and report files are outside of the monitored directory\n")
        user_input =input("Do you want to override these file? yes/no\n")
        if user_input=="no":
            sys.exit()
        elif user_input=="yes":
            
            if argument.hash_function not in["SHA-1", "MD-5", "sha1","md5"]:
                print("Use [SHA-1 or sha1] for sha1 hashing or [MD-5 or md5] for md5 hashing\n")
                sys.exit()
            else:
                
                for subdir, dirs, files in os.walk(argument.monitored_directory):
                    for filename in files:
                        filepath = subdir + os.sep + filename
                        st =os.stat(filepath)
                        ownername = pwd.getpwuid(st.st_uid).pw_name
                        
                        owner =getpwuid(os.stat(filepath).st_uid).pw_name
                        group = getgrgid(os.stat(filepath).st_gid).gr_name
                        creation_date =time.ctime(os.path.getctime(filepath))
                        last_modified = time.ctime(os.path.getmtime(filepath))
                        size =os.path.getsize(filepath)
                        mask = oct(st.st_mode & 0o777)#[-3:]
                    
                        if argument.hash_function in ["sha1","SHA-1"]:
                            hasher = hashlib.sha1()
                            with open(filepath, 'rb') as afile:
                                buf = afile.read()
                                hasher.update(buf)
                                message_digest =hasher.hexdigest()
                        elif argument.hash_function in ["md5","MD-5"]:
                            hasher = hashlib.md5()
                            with open(filepath, 'rb') as afile:
                                buf = afile.read()
                                hasher.update(buf)
                                message_digest =hasher.hexdigest()
                        file_info[filepath] ={"Path to file":filepath,"Size of file":size,"User owning file":owner,"Group owning file":group,"File permissions":mask,\
                            "File's last modification date":last_modified,"Hashing_function":argument.hash_function,"message_digest":message_digest}#,"Hash":"sha1","message_digest":hasher}
                        
                        i =i+1
                        count = count + 1
                        json_file = json.dumps(file_info, indent=4)
                        
                    for dir in dirs:
                        directory_path = subdir + os.sep + dir
                        st =os.stat(directory_path)
                        ownername = pwd.getpwuid(st.st_uid).pw_name
                    
                        owner =getpwuid(os.stat(directory_path).st_uid).pw_name
                        group = getgrgid(os.stat(directory_path).st_gid).gr_name
                        creation_date =time.ctime(os.path.getctime(directory_path))
                        last_modified = time.ctime(os.path.getmtime(directory_path))
                        size =os.path.getsize(directory_path)
                        mask = oct(st.st_mode)#[-3:]
                        
                        file_info[directory_path] ={"Path to file":directory_path,"Size of file":size,"User owning file":owner,"Group owning file":group,"File permissions":mask,"File's last modification date":last_modified}
                        j= j+1
                        count =count +1
                        json_file = json.dumps(file_info, indent=4) 
                        

    with open(argument.verification_file, "w") as fp:
        fp.write(json_file)
        print("Verification file generated\n")
    end_time1 =time.time()
    execution_time =end_time1-start_time1
    report_info["Full pathname to monitored directory"] = argument.monitored_directory
    #report_info["Full pathname to verification file"] = Path(argument.monitored_directory).absolute()
    report_info["Full pathname to verification file"] = os.path.abspath(argument.verification_file)
    report_info["Number of directories parsed"] = j

    report_info["Number of files parsed"] = i
    report_info["Time to complete the initialization mode"]= execution_time
    json_report_file = json.dumps(report_info, indent=4)
    with open(argument.report_file, "w") as rf:
        rf.write(json_report_file)
        print("Report file generated\n")
        print("Initialization mode successfully completed\n")

if argument.verification:
    print("Running in verification mode\n")
    start_time2 =time.time()
    if os.path.exists(argument.monitored_directory):
        print("Monitored Directory Exist\n")
    else:
        print("Specify a directory for siv to monitor and verify\n")
        sys.exit()
    file_size = os.path.getsize(argument.verification_file)
    if (os.path.exists(argument.verification_file)and file_size!=0):
        print("Verification file exist and has data to parse\n")
        print("The file size is: ", file_size)
    else:
        # ask =input("No Verification file found.Do you want to create one? yes/no\n")
        # if ask=="yes":
        #     #os.open(argument.report_file, os.O_CREAT, mode=511)
        #     os.open(argument.verification_file, os.O_CREAT, mode=0o0777)
        # else:
        print("Provide a verification file with data for the program to parse and verify\n")
        sys.exit()
    if os.path.exists(argument.report_file):
            print("Report file exist\n")
    else:
        ask =input("No report file found.Do you want to create one? yes/no\n")
        if ask=="yes":
            #os.open(argument.report_file, os.O_CREAT, mode=511)
            os.open(argument.report_file, os.O_CREAT, mode=0o0777)
        else:
            sys.exit()
    
    prefix = os.path.commonprefix([argument.verification_file,argument.report_file])
    if prefix==argument.monitored_directory:
        print("Verification and report files should not be inside the monitored_directory\n")
        sys.exit()
    else:
        print("All good.Verification and report files are outside of the monitored directory\n")
        decision =input("Do you want to override these file? yes/no\n")
        if decision=="no":
            sys.exit()
        elif decision=="yes":
            with open(argument.verification_file) as veri_file:
                veri= json.load(veri_file)
            with open(argument.report_file, "w") as rf:
                rf.write("Verification info begins\n")
                for subdir, dirs, files in os.walk(argument.monitored_directory):
                    for filename in files:
                        m=m+1
                        filepath = subdir + os.sep + filename
                        st =os.stat(filepath)
                        ownername = pwd.getpwuid(st.st_uid).pw_name
                        
                        owner =getpwuid(os.stat(filepath).st_uid).pw_name
                        group = getgrgid(os.stat(filepath).st_gid).gr_name
                        creation_date =time.ctime(os.path.getctime(filepath))
                        last_modified = time.ctime(os.path.getmtime(filepath))
                        size =os.path.getsize(filepath)
                        mask = oct(st.st_mode & 0o777)#[-3:]
                        
                        if filepath in veri.keys():

                            if size != veri[filepath]["Size of file"]:
                                rf.write("\nWarning!!!\n The file " + filepath + " has different size\n")
                                warnings = warnings+1
                            if owner != veri[filepath]["User owning file"]:
                                rf.write("\nWarning!!!\n The owner of file " + filepath + " has been changed\n")
                                warnings = warnings+1
                            
                            if group!= veri[filepath]["Group owning file"]:
                                rf.write("\nWarning!!!\n The group of file " + filepath + " has been changed\n")
                                warnings = warnings+1
                            if last_modified != veri[filepath][ "File's last modification date"]:
                                rf.write("\nWarning!!!\n" + filepath + " has different last modified date\n")
                                warnings = warnings+1
                            if mask!= veri[filepath]["File permissions"]:
                                rf.write("\nWarning!!!\n" + filepath + " has different accesss rights\n")
                                warnings = warnings+1
                            hash_type = veri[filepath]["Hashing_function"]
                            if hash_type in ["sha1","SHA-1"]:
                                hasher = hashlib.sha1()
                                with open(filepath, 'rb') as afile:
                                    buf = afile.read()
                                    hasher.update(buf)
                                    message_digest =hasher.hexdigest()
                                    if message_digest!= veri[filepath]["message_digest"]:
                                        rf.write("\nWarning!!!\n" + filepath + " has different message digest\n")
                                        warnings = warnings+1
                            elif hash_type in ["md5","MD-5"]:
                                hasher = hashlib.md5()
                                with open(filepath, 'rb') as afile:
                                    buf = afile.read()
                                    hasher.update(buf)
                                    message_digest =hasher.hexdigest()
                                    if message_digest!= veri[filepath]["message_digest"]:
                                        rf.write("\nWarning!!!\n" + filepath + " has different message digest\n")
                                        warnings = warnings+1
                        else:
                            rf.write("Warning!!!\n" + filepath + " has been added\n")
                            warnings = warnings+1
                    for dir in dirs:
                        n =n+1
                        directory_path = subdir + os.sep + dir
                        st =os.stat(directory_path)
                        ownername = pwd.getpwuid(st.st_uid).pw_name
                    
                        owner =getpwuid(os.stat(directory_path).st_uid).pw_name
                        group = getgrgid(os.stat(directory_path).st_gid).gr_name
                        creation_date =time.ctime(os.path.getctime(directory_path))
                        last_modified = time.ctime(os.path.getmtime(directory_path))
                        size =os.path.getsize(directory_path)
                        mask = oct(st.st_mode)#[-3:]
                        if directory_path in veri.keys():

                            if size != veri[directory_path]["Size of file"]:
                                rf.write("\nWarning!!!\n The directory " + directory_path + " has different size\n")
                                warnings = warnings+1
                            if owner != veri[directory_path]["User owning file"]:
                                rf.write("\nWarning!!!\n The owner of file " + directory_path + " has been changed\n")
                                warnings = warnings+1
                            if group!= veri[directory_path]["Group owning file"]:
                                rf.write("\nWarning!!!\n The group of file " + directory_path + " has been changed\n")
                                warnings = warnings+1
                            if last_modified != veri[directory_path][ "File's last modification date"]:
                                rf.write("\nWarning!!!\n" + directory_path + " has different last modified date\n")
                                warnings = warnings+1
                            if mask!= veri[directory_path]["File permissions"]:
                                rf.write("\nWarning!!!\n" + directory_path + " has different accesss rights\n")
                                warnings = warnings+1
                        else:
                            rf.write("\nWarning" + filepath + " has been added\n")
                            
                                
                for directory in veri.keys():

                    if os.path.exists(directory) == 0:
                        rf.write("Warning!!!\n " + directory + " has been deleted\n")
                        warnings = warnings+1

    end_time2 =time.time()
    execution=end_time2-start_time2
    verification_report["Full pathname to monitored directory"] = argument.monitored_directory
    verification_report["Full pathname to verification file"] = os.path.abspath(argument.verification_file)
    verification_report["Number of directories parsed"] = n
    verification_report["Number of files parsed"] = m
    verification_report["Number of warning issued"]= warnings
    verification_report["Time to complete the initialization mode"]= execution
    json_report = json.dumps(verification_report, indent=4)
    with open(argument.report_file, "a") as ff:
        #ff.write("Verification sats\n")
        ff.write(json_report)
        print("Verification mode successfully completed and report file generated\n")
