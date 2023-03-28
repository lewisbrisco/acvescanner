import os
import subprocess
import csv
import re

# Initialize the list of vulnerabilities
vulnerabilities = []

# Initialize the list of safe files
safe_list = []

# Initialize the list of directories
directories_to_scan = []

# liability statement
print("\nThe software provided is offered ‘as is’ and without warranty. This means that the user accepts all risks and responsibilities associated with the use of the software. The product is open source, which means that the user has access to the software's source code and can modify it as needed. However, the user should be aware that the software may not be error-free and that the developer(s) do not guarantee its performance or reliability. By using the software, the user agrees to accept all accountability for any consequences that may arise from its use. \nIn addition to the statement above, it is important to note that the developer(s) of this software shall not be held liable for any damages or losses that may result from the use or inability to use the software, including but not limited to, any direct, indirect, incidental, or consequential damages. The user understands and acknowledges that they use the software at their own risk and that the developer(s) of the software shall not be responsible for any harm or damage caused by the use of the software, even if the developer(s) have been advised of the possibility of such damages. The user assumes all liability for any losses or damages that may result from the use of the software.\n")


# this script finds the python version to ensure that it is compatible
# run the command
result = subprocess.run(['python', '--version'], stdout=subprocess.PIPE)
# get the output and decode it
output = result.stdout.decode('utf-8')
# extract the version number
version_string = output.strip().split(' ')[1]
# convert version string to tuple of ints
version_tuple = tuple(map(int, version_string.split('.')))
if version_tuple[0] < 3 & version_tuple[1] < 8:
    input("Python version is out of date! Please install python version 3.8 or above from python.org")
else:
    print("Installed python version (",version_string,") is compatible with this tool!")

#menu for permission to install prerequisites
def download_permission():
    print("")
    print("This program requires progressbar2 and cve-bin-tool to be downloaded, if they are already installed then nothing will be downloaded.")
    print("Do you wish to continue?")
    print("[y] Yes")
    print("[n] No - this will end the program")

download_permission_answer = "99"
while not download_permission_answer in ("y","n"):
    try:
        download_permission()
        download_permission_answer = str(input("Enter your preference: ")) 
        download_permission_answer = download_permission_answer.lower()
    except:
        download_permission_answer = "99"
if download_permission_answer == "y":
    subprocess.run(['python', '-m', 'ensurepip'], check=True)
    subprocess.run(['python', '-m', 'pip', 'install', '--upgrade', 'pip'], check=True)
    # Check if progressbar2 is installed, if not install it
    try:
        import progressbar
    except ImportError:
        subprocess.run(['python', '-m', 'pip', 'install', 'progressbar2'], check=True)
        import progressbar

    # Check if cve-bin-tool is installed, if not install it
    try:
        import cve_bin_tool
    except ImportError:
        subprocess.run(['python', '-m', 'pip', 'install', 'cve-bin-tool'], check=True)
        import cve_bin_tool
if download_permission_answer == "n":
    exit()


#menu for output choice
def firsttimesetup():
    print("")
    print("Perform first time set up?")
    print("[y] Yes")
    print("[n] No")
    print("[0] Exit the program")
first_time_option = "99"
while not first_time_option in ("0","y","n"):
    try:
        firsttimesetup()
        first_time_option = str(input("Enter your preference: ")) 
        first_time_option = first_time_option.lower()
    except:
        first_time_option = 99
if first_time_option == "y":
    subprocess.run(['cve-bin-tool'])
if first_time_option =="0":
    exit()

#menu to update cve-bin-tool database
def cve_menu():
    print("")
    print("Would you like to update the CVE database?")
    print("[y] Yes")
    print("[n] No")
    print("[0] Exit the program")
cve_option = "99"
while not cve_option in ("0","y","n"):
    try:
        cve_menu()
        cve_option = str(input("Enter your preference: ")) 
        cve_option = cve_option.lower()
    except:
        cve_option = 99
if cve_option == "y":
    subprocess.run(['cve-bin-tool'])
if cve_option =="0":
    exit()

#menu for output choice
def menu():
    print("")
    print("[1] Console Output")
    print("[2] File Output")
    print("[3] Both")
    print("[0] Exit the program")
option = 99
while not option in (0,1,2,3):
    try:
        menu()
        option = int(input("Enter your output preference: ")) 
    except:
        option = 99

if option ==0:
    exit()

#menu for FILE output choice
def menu_file():
    print("")
    print("[1] txt")
    print("[2] csv")
    print("[0] Exit the program")


option_menu = 99
if option == 2 or option == 3:
    while not option_menu in (1,2,0):
        try:
            menu_file()
            option_menu = int(input("Enter your output file preference: ")) 
        except:
            option_menu = 99

if option_menu==0:
    exit()

if option_menu == 1:
    file_type = "txt"
    # this script deletes the output file to be written to
    if os.path.exists('acves_output_file.txt'):
        # delete file
        os.remove('acves_output_file.txt')
        print(f"{'acves_output_file.txt'} deleted successfully")
    else:
        print(f"{'acves_output_file.txt'} does not exist")
if option_menu == 2:
    file_type = "csv"
    if os.path.exists('acves_output_file.csv'):
        # delete file
        os.remove('acves_output_file.csv')
        print(f"{'acves_output_file.csv'} deleted successfully")
    else:
        print(f"{'acves_output_file.csv'} does not exist")

#menu for file scan type choice
def menu_directory():
    print("")
    print("[1] Full Scan - Scan entire file system")
    print("[2] Threat Scan - Scan areas most likely to contain vulnerabilities")
    print("[3] Custom Scan - Scans multiple user defined file/ full directory")
    print("[4] Single File Scan - Scans one user defined file/ full directory")
    print("[0] Exit the program")
    
#logic for file scan type choice
option_directory = 99
while not option_directory in (1,2,3,4,0):
    try:
        menu_directory()
        option_directory = int(input("Enter your output file preference: ")) 
    except:
        option_directory = 99

if option_directory==0:
    exit()

def custom_single_directory(directories_to_scan):
    while True:
        path = input("Enter the path to the directory you want to select: ")
        if os.path.isdir(path):
            directories_to_scan.append(path)
            choice = input("Do you want to select another directory? (y/n): ")
            if choice.lower() == "n":
                return
        else:
            print("Invalid directory path. Please try again.")


def select_single_directory(directories_to_scan):
    while True:
        path = input("Enter the path to the directory you want to select: ")
        if os.path.isdir(path):
            directories_to_scan.append(path)
            return
        else:
            print("Invalid directory path. Please try again.")
            print("")

# Scans entire file system
if option_directory==1:
    for drive in ['A:', 'B:', 'C:', 'D:', 'E:', 'F:', 'G:', 'H:', 'I:', 'J:', 'K:', 'L:', 'M:', 'N:', 'O:', 'P:', 'Q:', 'R:', 'S:', 'T:', 'U:', 'V:', 'W:', 'X:', 'Y:', 'Z:']:
        if os.path.isdir(drive+'\\'):
            directories_to_scan.append(drive+'\\')
    
# Scan the directories where vulnerable programs / services are likely to be installed
if option_directory==2:
    directories_to_scan = ['\\$RECYCLE.BIN', '\\Temp', '\\Windows', 'Program Files', '\\Program Files (x86)', '\\Users']
    print (directories_to_scan)
    
# Scans one user defined directory where vulnerable programs / services are likely to be installed
if option_directory==3:
    custom_single_directory(directories_to_scan)
# Scans multiple user defined directory where vulnerable programs / services are likely to be installed
if option_directory==4:
    select_single_directory(directories_to_scan)

print ("")
try:
    def process_files(files, root):
        # Use progressbar2 to create a progress bar
        with progressbar.ProgressBar(max_value=len(files)) as bar:  # Set max_value to the length of the files list
            # Initialize the current progress variable
            current_progress = 0
            for file in files:
                # Check if path is a file and is accessible
                file_path = os.path.join(root, file)
                if os.path.isfile(file_path) and os.access(file_path, os.R_OK):  # Check if the file exists and is accessible
                    # query CVE database with file
                    print(file_path)
                    output = subprocess.run(['cve-bin-tool', '--offline', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    # check for matches
                    if output.stdout:
                        vulnerabilities.append([file_path, output.stdout])
                # Update the progress bar
                current_progress += 1  # Increment the progress variable
                bar.update(current_progress)  # Pass the current progress to the update method
            return len(files)  # return the number of files processed
except PermissionError:
    pass

# Scan the directories where vulnerable programs / services are likely to be installed
#directories_to_scan = ["C:\\Users\\Lewis\\Desktop\\Dissertation\\application-check\\jre\\bin"]

for directory in directories_to_scan:
    for root, dirs, files in os.walk(directory):
        # Process the files in the current directory
        num_files_processed = process_files(files, root)

cves = []
i=1

# Print list of vulnerabilities
if not vulnerabilities:
    print('No vulnerabilities found.')
else:
    print('Vulnerabilities found:')
    if option == 1 or option == 3: # if console output is chosen this code will print the output
            print('A CVE number is used to identify each cybersecurity vulnerability in the CVE Database, which is a comprehensive collection of publicly disclosed flaws. CVE offers a dependable and practical way for vendors, businesses, academics, and other interested parties to exchange information about security issues. Enterprises typically manage their vulnerability programmes by planning and prioritising their efforts using CVE along with CVSS scores.')
            print("")
            print('Common Vulnerability Scoring System (CVSS) Score is a grading that measures the seriousness of security vulnerabilities in a computer system')
            print('It uses a scale of 0 to 10 with five categories')
            print('None = 0')
            print('Low = 0.1-3.9') 
            print('Medium = 4.0-6.9')
            print('High = 7.0-8.9')
            print('Critical = 9.0-10.0')
            print('None means no vulnerability while critical is extremely severe and could cause catastrophic damage') 

            for vulnerability in vulnerabilities:
                path = vulnerability[0].strip()  # Extract path and remove leading/trailing whitespace

                description = re.findall(r'CVE BINARY TOOL version:(?:(?!Root 0 :)[\d.\n\s\S])*', vulnerability[1].decode('latin-1').strip())
                description = description[0].strip('\r\n') # Remove leading/trailing line breaks and carriage returns
                
                cve_list = re.findall(r'CVE-\d{4}-\d{4,7}', description)
                path = vulnerability[0].strip()
    
                if len(cve_list) > 0:
                    print('Vulnerabile File Number #'+str(i))
                    i += 1
                    print('This is the path where the vulnerabilities were found')
                    print(path)
                    print("")
                    print('This is a table outlining the severity of each vulnerability found')
                    print(description)
                    print("")
                    #print(cve_list) #this line writes the list of vulnerabilities found
                    print('Follow the links below to find more information on each vulnerability found:')
                    for cve_number in range(len(cve_list)):
                        try:
                            cve_url = "https://www.cvedetails.com/cve/" + cve_list[cve_number]
                            print(cve_url)
                        except:
                            print()

                if len(cve_list) == 0:
                    safe_list.append([path])

                cve_list = []
                print("")
            print('END OF VULNERABILITY LIST')
            print("-" * 100)
            print('')
            print('ALL FILES WITH NO CVE VULNERABILITIES FOUND')
            for item in safe_list:
                print(item)
    i = 1
    if option == 2 or option == 3: # if file output is chosen this code will output to text file
        with open('acves_output_file.'+file_type, 'a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)  # create a writer object
            file.write('')
            writer.writerow(['A CVE number is used to identify each cybersecurity vulnerability in the CVE Database, which is a comprehensive collection of publicly disclosed flaws. CVE offers a dependable and practical way for vendors, businesses, academics, and other interested parties to exchange information about security issues. Enterprises typically manage their vulnerability programmes by planning and prioritising their efforts using CVE along with CVSS scores.'])
            writer.writerow("")
            writer.writerow(['Common Vulnerability Scoring System (CVSS) Score is a grading that measures the seriousness of security vulnerabilities in a computer system'])
            writer.writerow(['It uses a scale of 0 to 10 with five categories'])
            writer.writerow(['None = 0'])
            writer.writerow(['Low = 0.1-3.9']) 
            writer.writerow(['Medium = 4.0-6.9'])
            writer.writerow(['High = 7.0-8.9'])
            writer.writerow(['Critical = 9.0-10.0'])
            writer.writerow(['None means no vulnerability while critical is extremely severe and could cause catastrophic damage']) 

            for vulnerability in vulnerabilities:
                path = vulnerability[0].strip()  # Extract path and remove leading/trailing whitespace

                description = re.findall(r'CVE BINARY TOOL version:(?:(?!Root 0 :)[\d.\n\s\S])*', vulnerability[1].decode('latin-1').strip())
                description = description[0].strip('\r\n') # Remove leading/trailing line breaks and carriage returns
                
                cve_list = re.findall(r'CVE-\d{4}-\d{4,7}', description)
                path = vulnerability[0].strip()
                
                if len(cve_list) > 0:
                    writer.writerow(['Vulnerabile File Number #'+str(i)])
                    i += 1
                    writer.writerow(['This is the path where the vulnerabilities were found'])
                    writer.writerow([path])
                    writer.writerow("")
                    writer.writerow(['This is a table outlining the severity of each vulnerability found'])
                    writer.writerow([description])
                    writer.writerow("")
                    #writer.writerow([cve_list]) #this line writes the list of vulnerabilities found
                    writer.writerow(['Follow the links below to find more information on each vulnerability found:'])
                    for cve_number in range(len(cve_list)):
                        try:
                            cve_url = "https://www.cvedetails.com/cve/" + cve_list[cve_number]
                            writer.writerow([cve_url])
                        except:
                            print()

                if len(cve_list) == 0:
                    safe_list.append([path])   

                cve_list = []
                writer.writerow("")
            writer.writerow(['END OF VULNERABILITY LIST'])
            writer.writerow(["-" * 100])
            writer.writerow("")
            writer.writerow(['ALL FILES WITH NO CVE VULNERABILITIES FOUND'])
            for item in safe_list:
                writer.writerow([item])
    if option == 2 or option == 3:
        file.close()
    
print("-" * 100)