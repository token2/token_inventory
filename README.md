
# Entra ID - Hardware token inventory portal

## Overview
This is a simple, lightweight web application built in PHP to manage hardware OATH tokens using the Microsoft Graph API. It includes features such as listing tokens, importing token configurations via JSON files, and providing an intuitive and responsive interface with Bootstrap.

---

## Features
- **Authentication**:
  - Form-based password protection for secure access.
- **Token Management**:
  - View a list of hardware OATH tokens.
  - Includes key details like Serial Number, Device (Manufacturer/Model), Assigned User, Status, and Last Used.
- **Import Functionality**:
  - Upload and import tokens using a JSON file.
- **Responsive Design**:
  - Utilizes [Bootstrap](https://getbootstrap.com/) for a clean and responsive UI.
- **Interactive Table**:
  - Integrated with [DataTables](https://datatables.net/) for sorting, searching, and pagination.

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/hardware-token-management.git
   cd hardware-token-management
   ```

2. Update the configuration in `index.php`:
   - Replace the following placeholders with your own values:
	$tenantId = 'YOUR_TENANT_ID';
	$clientId = 'YOUR_CLIENT_ID';
	$clientSecret = 'YOUR_CLIENT_SECRET';

	$valid_username = 'username to access this app'; // Set your username
	$valid_password = 'password to access the app'; // Set your password



3. Deploy the application on a PHP-compatible server (e.g., Apache, Nginx).

4. Access the application in your browser.

---

## Usage
1. **Login**:
   - Access the portal using the predefined username and password (`admin/password123` by default).
   - Update these credentials in `index.php`.

2. **Import Tokens**:
   - Use the **Import Tokens** button to upload a JSON file with the token details. This format is available in Token2's seed request form.
   - Example JSON format:
     ```json
     [
         {
             "serialNumber": "8659623852751",
             "secretKey": "ABC1234567890DEF",
             "manufacturer": "Token2",
             "model": "C202",
             "timeIntervalInSeconds": 30,
             "hashFunction": "hmacsha1"
         }
     ]
     ```

3. **View Tokens**:
   - Explore the table with token details.
   - Use search and sorting features provided by DataTables for quick navigation.

---

## Screenshots
**Login Page**  
[Insert Screenshot Here]

**Token List**  
[Insert Screenshot Here]

**Import Modal**  
[Insert Screenshot Here]

---


## License
This project is open-source and available under the [MIT License](LICENSE).

---

## Acknowledgments
- [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/overview)
- [Token2](https://www.token2.com) for hardware tokens
- [Bootstrap](https://getbootstrap.com/) for responsive design
- [DataTables](https://datatables.net/) for interactive table functionality

---

## Contact
For any questions or suggestions, please contact me via support {at} token2.com or open an issue in this repository.
