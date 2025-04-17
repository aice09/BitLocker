# BitLocker

This tool checks if your Windows device meets the requirements for BitLocker encryption and provides prompts based on the current system status.

---

## 🔍 Overview

The checker evaluates:

- TPM status and version
- Firmware type (UEFI)
- Secure Boot status
- OS version
- Free storage
- Tanium installation
- Registry readiness
- BitLocker encryption status

Depending on the result, you'll see one of the following outputs:

---

## ✅ Situation 1: All Requirements Passed, BitLocker Enabled
```powershell
////////Checking Requirements////////
... (All items show PASSED)

////////BitLocker Status///////
BitLocker Status - Fully Encrypted
BitLocker Volume Status - Protected On Drive C
```

**What this means:**  
Your system is fully compliant and already encrypted with BitLocker.

> ✅ No further action is needed. Thank you for keeping your drive secured.

---

## 🛠️ Situation 2: Registry Not Installed, BitLocker Not Enabled
```powershell
////////Checking Requirements////////
... Registry: Not Installed (FAILED)

////////BitLocker Status///////
BitLocker Status - Fully Decrypted
BitLocker Volume Status - Protected Off

//////////INSTALLING///////////
- Installing registry...
```


**What this means:**  
The system is ready, but the required registry key was missing.

> 🛠 The tool installs the registry automatically.  
> ⏳ Wait **at least 30 minutes** for Tanium to process and add your recovery password protector.

---

## 🔁 Situation 3: Registry Installed, BitLocker Still Not Enabled
```powershell
////////Checking Requirements////////
... Registry: Installed (PASSED)

////////BitLocker Status///////
BitLocker Status - Fully Decrypted
BitLocker Volume Status - Protected Off

//////////INSTALLING///////////
- Re-Installing registry...
```

**What this means:**  
The registry exists, but BitLocker is still off.

> 🔄 The registry is re-installed to ensure it's properly configured.  
> ⏳ Wait **at least 30 minutes** for Tanium to register the recovery password protector.

---

## 🔐 Situation 4: BitLocker Not Yet Encrypted (Prompt User)

```powershell
////////Checking Requirements////////
... Registry: Installed (PASSED)

////////BitLocker Status///////
BitLocker Status - Fully Decrypted
BitLocker Volume Status - Protected On

//////////Encrypting///////////
- Do you want to enable BitLocker?
```

**What this means:**  
Everything is ready. The system prompts the user to enable BitLocker.

> 📝 Follow the on-screen prompt.  
> 🔑 You’ll be asked to enter a password to secure your drive.

---
## 🔓 Decryption Option

If needed, the tool can **disable BitLocker** and decrypt the drive. This process may take some time, depending on the drive size and performance.

### How It Works

- Automatically starts decryption using `Disable-BitLocker`
- Shows live progress with `Write-Progress`
- Logs every step in `C:\BitLockerStatus.log`
- Reboots the system upon full decryption

# 📄 Log File

All actions performed by the script are logged in:
```
C:\BitLockerStatus.log
```
Use this log to troubleshoot errors, check the status of registry installation, encryption, decryption, and other events.

---

## ℹ️ Support

If you experience issues or aren't sure how to proceed, please contact your IT support team.

---

