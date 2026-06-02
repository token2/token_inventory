# TOTP Token Inventory: Automate Token2 Classic OATH Token Activation in Microsoft Entra ID

---

## **🚀 Key Feature: Automatic Token Activation**
The **TOTP Token Inventory** app now supports **automatic activation** of Token2 Classic OATH tokens during CSV upload. When tokens are assigned to users in the CSV, the app will:
- Retrieve the **secret key** of each token.
- Calculate the **current OTP code** (for both SHA-1 and SHA-256).
- Send the code to **Microsoft Graph API** for activation.

This **eliminates the need for separate bulk activation tools**, making deployment **faster and more efficient**.

---

## **1. Overview**
The **TOTP Token Inventory** app is a **powerful, open-source PHP tool** designed to **automate the management and activation** of **Token2 Classic OATH hardware tokens** in Microsoft Entra ID (Azure AD). Unlike Microsoft’s official tools, this app offers:
- A **user-friendly web interface**.
- **Bulk operations** (CSV/JSON import).
- **Automatic token activation** during CSV upload.
- **Self-service activation** for end users.
- **SHA-1 and SHA-256 support**.
- **Detailed logging** for auditing.

---

## **2. Comparison: TOTP Token Inventory vs. Microsoft’s Official Tools**

| Feature                     | Microsoft CSV Blade (Admin Center) | Microsoft Graph API | TOTP Token Inventory (PHP App) |
|-----------------------------|-----------------------------------|---------------------|--------------------------------|
| **Automatic Activation**    | ❌ No                              | ❌ No                | ✅ **Yes** (during CSV upload) |
| **Bulk Import**             | ✅ Yes (CSV only)                 | ✅ Yes               | ✅ **Yes** (CSV/JSON)          |
| **Self-Service Activation** | ❌ No                              | ✅ Yes               | ✅ **Yes**                     |
| **SHA-256 Support**         | ❌ No                              | ✅ Yes               | ✅ **Yes**                     |
| **User-Friendly UI**         | ✅ Basic                           | ❌ No (API only)     | ✅ **Full Web UI**             |
| **Detailed Logging**        | ❌ No                              | ❌ No                | ✅ **Yes**                     |
| **No Scripting Required**   | ✅ Yes                             | ❌ No                | ✅ **Yes**                     |
| **Open-Source**             | ❌ No                              | ❌ No                | ✅ **Yes**                     |
| **Bundled Windows App**     | ❌ No                              | ❌ No                | ✅ **Yes**                     |

---

## **3. Why Choose TOTP Token Inventory?**
- **Automatic Activation**: The **only solution** that activates tokens during CSV import, eliminating manual steps.
- **User-Friendly**: No scripting required; accessible via a **web UI**.
- **Bulk Operations**: Import and assign **hundreds of tokens at once**.
- **Self-Service**: Users activate tokens **without admin intervention**.
- **SHA-256 Support**: Handles both **SHA-1 and SHA-256** tokens.
- **Open-Source**: Free to use, modify, and deploy.
- **Bundled App**: Run on **Windows without a server** using PHPDesktop.

---

## **4. Pre-Requisites**
- **Server**: Works on **any server with PHP 7.4+** (Linux/Windows).
- **Bundled App**: Also available as a **PHPDesktop-based Windows app** (no server required).
- **Microsoft Entra ID**:
  - **Tenant ID**, **Client ID**, and **either a Client Secret or a Certificate** (from an App Registration with **Graph API permissions**).
  - **Authentication method**: The app supports **two ways** to authenticate the App Registration:
    - **Client Secret** – the original, simplest method.
    - **Certificate** – a **certificate-based credential** (signed JWT client assertion). More secure, as no shared secret is stored, and recommended for production. See **Section 6.F**.
  - **Required permissions**:
    - `Policy.ReadWrite.AuthenticationMethod`
    - `UserAuthenticationMethod.ReadWrite.All`
    - `User.Read.All`
    - `Directory.Read.All`
  - **Admin consent** for the above permissions.
- **Token2 Classic Tokens**: **CSV file** with token details (serial number, secret key, UPN, etc.).
  - **CSVs for factory-set seeds are provided by Token2** via the seed request procedure.

---

## **5. Supported Formats**

| Format  | Use Case                                  | Description                                                                                     |
|---------|-------------------------------------------|-------------------------------------------------------------------------------------------------|
| **CSV**  | Bulk import with pre-assignment and **automatic activation** | Admins can **pre-assign tokens to users** in the CSV. The app **automatically activates** these tokens by calculating the OTP code and sending it to Graph API. **CSVs for factory-set seeds are provided by Token2**. |
| **JSON** | Self-service repository                   | Tokens are uploaded to a **shared repository**. Users activate them via **Security Info**.     |

---

## **6. Step-by-Step Guide**

### **A. Initial Setup**
1. **Download and install**:
   - Deploy on a **PHP server** or use the **bundled Windows app**.
2. **Enter credentials**:
   - Provide your **Tenant ID** and **Client ID**.
   - Choose an **Authentication method**: **Client Secret** or **Certificate** (see **Section 6.F** to set up a certificate).
3. **Verify permissions**:
   - Ensure the app has the required **Graph API permissions** and admin consent.

### **B. Importing Tokens**
1. **Prepare your CSV**:
   - Include columns: `upn`, `serial number`, `secret key`, `timeinterval`, `manufacturer`, `model`.
   - **Pre-assign tokens** by including user UPNs. The app will **automatically activate** these tokens.
   - **CSVs for factory-set seeds are provided by Token2** via the seed request procedure.
2. **Upload CSV/JSON**:
   - Use the **web interface** to upload your file.
   - The app **automatically converts CSV to JSON** for Graph API and **activates pre-assigned tokens**.

### **C. Assigning Tokens**
- **Search for users** and assign tokens via the **web UI**.
- **Bulk assignment**: Assign multiple tokens at once using the CSV pre-assignment feature.

### **D. Activating Tokens**
- **Automatic activation**: When tokens are pre-assigned in the CSV, the app **automatically activates them** by calculating the OTP code and sending it to Graph API.
- **User self-service**: Users activate tokens via the **web form** or their **Security Info page**.
- **Auto-generation**: The app can **auto-generate TOTP codes** from the secret key for activation.

### **E. Managing Tokens**
- **Unassign/Delete**: Remove tokens from users or delete them permanently.
- **Logs**: View detailed logs for all operations.

---

### **F. Certificate-Based Authentication (Optional)**
Instead of a **Client Secret**, you can authenticate the App Registration using a **certificate**. The app builds a **signed JWT client assertion** and sends it to Entra ID — no shared secret is stored on disk.

**What you need:**
- A **public certificate** (`.cer`) uploaded to your App Registration.
- The matching **private key in PEM format** (`-----BEGIN PRIVATE KEY-----`), readable by the PHP process.
- The certificate **thumbprint** (hex), shown by Entra ID after upload.

**1. Generate a certificate (Windows, PowerShell):**

Use the bundled helper script `Generate-Token2Cert.ps1` (PowerShell 7+) or `Generate-Token2Cert-51.ps1` (Windows PowerShell 5.1, uses OpenSSL):

```powershell
powershell -ExecutionPolicy Bypass -File .\Generate-Token2Cert.ps1
```

This produces:
- `token2_public.cer` – the **public certificate** to upload to Entra ID.
- `private_key.pem` – the **private key** for the app.
- A printed **thumbprint** to paste into the app.

> **Note:** If a **SafeNet / Thales token dialog** appears, it means a hardware-token provider is being used. The scripts force the **Microsoft software provider** (`-Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"`) to avoid this. Hardware-token-stored keys cannot be exported to PEM and are not supported by this app.

Alternatively, generate everything in one step with **OpenSSL**:

```powershell
openssl req -x509 -newkey rsa:2048 -keyout private_key.pem -out token2_public.cer -days 730 -nodes -subj "/CN=Token2 Inventory App"
openssl x509 -in token2_public.cer -noout -fingerprint -sha1
```

**2. Upload the public certificate to Entra ID:**
- Go to **Azure Portal → App registrations → your app → Certificates & secrets → Certificates → Upload certificate**.
- Upload `token2_public.cer`.
- Entra ID displays the **thumbprint** — confirm it matches the one printed by the script.

**3. Configure the app:**
- On the credentials screen (or **Settings**), set **Authentication method** to **Certificate**.
- **Private key file path**: full path to `private_key.pem` (e.g. `C:\token2\private_key.pem`).
- **Private key passphrase**: only if you created an **encrypted** PEM; otherwise leave blank.
- **Certificate thumbprint**: paste the hex thumbprint.

**4. Security notes:**
- Treat `private_key.pem` like a password — anyone with it can authenticate as your app.
- Store the key **outside the web root** when running on a web server.
- A **self-signed certificate is sufficient**, because Entra ID trusts it by explicit upload (not by a CA chain).
- Set a reminder before the certificate **expiry date** — token requests fail once it expires.

---

## **7. Best Practices**
- **Backup credentials**: Store your **Client Secret** or **private key (PEM)** securely.
- **Prefer certificates in production**: Certificate-based auth avoids storing a shared secret and is generally more secure than a Client Secret.
- **Test with a small batch**: Validate the workflow before bulk importing.
- **Monitor logs**: Use logs to audit operations and troubleshoot issues.
- **Keep permissions updated**: Ensure Graph API permissions are current.

---

## **8. Conclusion**
The **TOTP Token Inventory** app is the **only solution** that offers **automatic token activation** during CSV import, making it the **most efficient way** to deploy and manage **Token2 Classic OATH tokens** in Microsoft Entra ID. With its **user-friendly interface**, **bulk operations**, and **self-service activation**, it provides a **complete, scalable, and auditable** solution for organizations of all sizes.

**Say goodbye to manual activation processes—TOTP Token Inventory automates everything.**

 
