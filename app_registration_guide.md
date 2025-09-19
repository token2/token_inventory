# Azure App Registration Guide for OATH Token Management

This guide walks you through creating an Azure App Registration with the necessary permissions to manage hardware OATH tokens in Microsoft Entra ID using the Microsoft Graph API.

## Prerequisites

- **Global Administrator** or **Application Administrator** role in your Azure AD tenant
- Access to the Azure portal (https://portal.azure.com)
- Understanding of OAuth 2.0 and Microsoft Graph API basics

## Step 1: Create the App Registration

### 1.1 Navigate to Azure Portal
1. Open a web browser and go to https://portal.azure.com
2. Sign in with your Global Administrator or Application Administrator account
3. In the search bar, type **"App registrations"** and select it from the results

### 1.2 Create New Registration
1. Click **"+ New registration"**
2. Fill in the application details:
   - **Name**: `OATH Token Manager` (or your preferred name)
   - **Supported account types**: Select **"Accounts in this organizational directory only"**
   - **Redirect URI**: 
     - For PowerShell/Desktop apps: Leave blank or add `http://localhost`
     - For Web apps: Add your application URL (e.g., `https://yourdomain.com/callback`)
3. Click **"Register"**

### 1.3 Note Important Values
After registration, copy and save these values (you'll need them later):
- **Application (client) ID**
- **Directory (tenant) ID**
- **Object ID**

## Step 2: Configure API Permissions

### 2.1 Add Microsoft Graph Permissions
1. In your app registration, click **"API permissions"** in the left menu
2. Click **"+ Add a permission"**
3. Select **"Microsoft Graph"**
4. Choose **"Application permissions"** (for service-to-service authentication)

### 2.2 Required Permissions for OATH Token Management

Add the following **Application permissions**:

#### Core Permissions
| Permission | Purpose | Justification |
|------------|---------|---------------|
| `Directory.Read.All` | Read directory data | Required to access authentication method devices |
| `User.Read.All` | Read all users' full profiles | Needed to list and search users for token assignment |
| `User.ReadWrite.All` | Read and write all users' full profiles | Required for assigning and activating tokens |

#### Authentication Method Permissions (if available)
| Permission | Purpose | Justification |
|------------|---------|---------------|
| `AuthenticationMethod.Read.All` | Read authentication methods | View existing authentication methods |
| `AuthenticationMethod.ReadWrite.All` | Manage authentication methods | Full management of OATH tokens |

### 2.3 Add Each Permission
For each permission listed above:
1. Click **"+ Add a permission"**
2. Select **"Microsoft Graph"**
3. Choose **"Application permissions"**
4. Search for the permission name (e.g., "Directory.Read.All")
5. Check the permission checkbox
6. Click **"Add permissions"**

### 2.4 Grant Admin Consent
**⚠️ Critical Step**: After adding all permissions:
1. Click **"Grant admin consent for [Your Organization]"**
2. Click **"Yes"** to confirm
3. Verify all permissions show **"Granted for [Your Organization]"** with green checkmarks

## Step 3: Create Client Secret (for Server-to-Server Apps)

### 3.1 Add Client Secret
1. Click **"Certificates & secrets"** in the left menu
2. Under **"Client secrets"**, click **"+ New client secret"**
3. Add a description: `OATH Token Manager Secret`
4. Select expiration: **"24 months"** (recommended for production)
5. Click **"Add"**

### 3.2 Copy Secret Value
**⚠️ Important**: Copy the secret **Value** immediately (it won't be shown again)
- Store it securely (e.g., Azure Key Vault, secure password manager)
- Never store it in source code or configuration files

## Step 4: Configure Authentication (Optional)

### 4.1 For Interactive Authentication (PowerShell GUI)
1. Click **"Authentication"** in the left menu
2. Click **"+ Add a platform"**
3. Select **"Mobile and desktop applications"**
4. Check the redirect URI: `https://login.microsoftonline.com/common/oauth2/nativeclient`
5. Click **"Configure"**

### 4.2 Advanced Settings
Under **"Advanced settings"**:
- **Allow public client flows**: Set to **"Yes"** (for PowerShell apps)
- **Supported account types**: Ensure it matches your organization needs

## Step 5: Verify Configuration

### 5.1 Final Permission Check
Your app should have these permissions with admin consent:
- ✅ `Directory.Read.All` - Granted
- ✅ `User.Read.All` - Granted  
- ✅ `User.ReadWrite.All` - Granted

### 5.2 Test API Access
Use Microsoft Graph Explorer to test:
1. Go to https://developer.microsoft.com/graph/graph-explorer
2. Sign in with your app credentials
3. Test query: `GET https://graph.microsoft.com/beta/directory/authenticationMethodDevices/hardwareOathDevices`

## Step 6: Configure Your Application

### 6.1 For PHP Web Application
Update your `index.php` configuration:

```php
// Configuration
$tenantId = 'your-tenant-id-here';        // Directory (tenant) ID
$clientId = 'your-client-id-here';        // Application (client) ID  
$clientSecret = 'your-client-secret-here'; // Client secret value
```

### 6.2 For PowerShell GUI Application
Update the PowerShell script configuration:

```powershell
$script:config = @{
    TenantId = "your-tenant-id-here"      # Directory (tenant) ID
    ClientId = "your-client-id-here"      # Application (client) ID
    Scopes = @(
        "https://graph.microsoft.com/Directory.Read.All",
        "https://graph.microsoft.com/User.Read.All", 
        "https://graph.microsoft.com/User.ReadWrite.All"
    )
}
```

## Step 7: Security Best Practices

### 7.1 Credential Security
- **Never store secrets in source code**
- Use Azure Key Vault for production secrets
- Implement proper secret rotation (before expiry)
- Use Managed Identities when possible

### 7.2 Access Control
- **Principle of least privilege**: Only assign necessary permissions
- **Regular access reviews**: Periodically review app permissions
- **Monitoring**: Enable audit logs for app authentication

### 7.3 Certificate Authentication (Recommended for Production)
Instead of client secrets, use certificates:
1. Generate X.509 certificate
2. Upload public key to **"Certificates & secrets"**
3. Use private key in your application
4. Certificates are more secure than secrets

## Step 8: Troubleshooting Common Issues

### 8.1 Permission Errors
**Error**: `Insufficient privileges to complete the operation`
**Solution**: 
- Verify admin consent was granted
- Check that all required permissions are added
- Ensure using Application permissions, not Delegated

### 8.2 Authentication Errors
**Error**: `invalid_client` or `unauthorized_client`
**Solution**:
- Verify Client ID and Client Secret are correct
- Check Tenant ID matches your organization
- Ensure app registration is not disabled

### 8.3 API Access Errors
**Error**: `Forbidden` or `Access denied`
**Solution**:
- Confirm the beta endpoint is accessible: `/beta/directory/authenticationMethodDevices/`
- Verify your tenant has hardware OATH tokens enabled
- Check API permissions include directory access

## Step 9: API Endpoints Reference

Your app registration will have access to these Microsoft Graph endpoints:

### Token Management Endpoints
```
# List all hardware OATH devices
GET /beta/directory/authenticationMethodDevices/hardwareOathDevices

# Create hardware OATH devices (bulk import)  
PATCH /beta/directory/authenticationMethodDevices/hardwareOathDevices

# Assign token to user
POST /beta/users/{userId}/authentication/hardwareOathMethods

# Activate token
POST /beta/users/{userId}/authentication/hardwareOathMethods/{tokenId}/activate

# Get users for assignment
GET /v1.0/users
```

## Step 10: Monitoring and Maintenance

### 10.1 Regular Tasks
- **Monitor secret expiration** (set calendar reminders)
- **Review audit logs** for unusual activity
- **Update permissions** if Microsoft adds new OATH-specific scopes
- **Test functionality** after Azure AD updates

### 10.2 Audit Logging
Enable and monitor these logs:
- **Sign-in logs**: Track app authentication
- **Audit logs**: Monitor permission changes
- **Application logs**: Review API usage patterns

---

## Quick Reference Card

**App Registration Summary:**
- **App Type**: Web application / Public client
- **Required Permissions**: `Directory.Read.All`, `User.Read.All`, `User.ReadWrite.All`
- **Authentication**: Client credentials (secret/certificate)
- **Admin Consent**: ✅ Required
- **API Version**: Microsoft Graph Beta

**Key Files to Update:**
- `index.php`: Update tenant ID, client ID, client secret
- PowerShell script: Update configuration section
- Store secrets securely (never in source control)

---

*This app registration will provide full access to manage hardware OATH tokens including import, assignment, and activation capabilities through Microsoft Graph API.*