import os
import time

def create_suspicious_file(folder_path):
    file_path = os.path.join(folder_path, "suspicious_file.txt")
    with open(file_path, "w") as f:
        f.write("This is a suspicious file.")

def modify_suspicious_file(folder_path):
    file_path = os.path.join(folder_path, "suspicious_file.txt")
    with open(file_path, "a") as f:
        f.write("\nModifying the suspicious file.")

def create_suspicious_process(folder_path):
    while True:
        create_suspicious_file(folder_path)
        time.sleep(5)
        modify_suspicious_file(folder_path)
        time.sleep(5)

if __name__ == "__main__":
    folder_path = os.path.dirname(os.path.abspath(__file__))
    create_suspicious_process(folder_path)
