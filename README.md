# ConvertTo-NT

`ConvertTo-NT` is a PowerShell function that converts a given string into its NT hash equivalent using the NTLM hashing algorithm. This can be particularly useful in security-related tasks where you need to generate or verify NT hashes for passwords.

## Usage

Load `ConvertTo-NT` in memory

```powershell
IEX(New-Object System.Net.WebClient).DownloadString("https://raw.githubusercontent.com/The-Viper-One/ConvertTo-NT/main/ConvertTo-NT.ps1")
```
Convert a string to an NT hash
```powershell
# Example 1
ConvertTo-NT -string "Password123"

# Example 2
"Password123" | ConvetTo-NT
```
