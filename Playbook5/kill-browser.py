#!/usr/bin/python3
# Playbook 5 - Active Response: kill browser (Windows Agent)
# File nguon de build thanh .exe bang PyInstaller.
#
# Build:
#   pip install pyinstaller
#   pyinstaller --onefile kill-browser.py
#   -> tao ra dist\kill-browser.exe
#
# Trien khai:
#   Copy dist\kill-browser.exe -> C:\Program Files (x86)\ossec-agent\active-response\bin\kill-browser-windows.exe
#   (ten file .exe phai TRUNG ten <command> trong ossec.conf)
#
# Ly do dung .exe: Wazuh 4.2+ khong thuc thi truc tiep script .cmd/.bat cho
# Active Response tren Windows (loi 1317), bat buoc dong goi thanh .exe.

import os

LOG = r"C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

with open(LOG, "a") as f:
    f.write("kill-browser triggered\n")

os.system('taskkill /F /IM msedge.exe')
os.system('taskkill /F /IM chrome.exe')

with open(LOG, "a") as f:
    f.write("kill-browser done\n")
