
# Entra ID - Hardware token inventory portal

## Overview

This is a simple, lightweight web application built in PHP to manage hardware OATH tokens using the Microsoft Graph API. It includes features such as listing tokens, importing token configurations via JSON files, and providing an intuitive and responsive interface with Bootstrap.
This repository serves as an excellent example of leveraging the Microsoft Graph API programmatically, going beyond the basic capabilities of the Graph API Explorer. By integrating direct API calls into a functional PHP application, it demonstrates how developers can interact with Microsoft Graph to manage hardware OATH tokens in real-world scenarios. The application showcases practical use cases such as fetching token details, importing configurations via JSON, and providing an intuitive UI for users—all while illustrating how to securely authenticate and work with the Graph API in a production-ready environment. 
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

## Usage
1. **Login**:
   - Access the portal using the predefined username and password (`admin/password123` by default).
   - Update these credentials in `index.php`.

2. **Import Tokens**:
   - Use the **Import Tokens** button to upload a JSON file with the token details. This format is available in Token2's seed request form. More information is available [here](https://www.token2.swiss/site/page/classic-hardware-tokens-for-entra-id-mfa-graph-api-method-with-self-service-and-sha-256-tokens-support). 
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
![image](https://github.com/user-attachments/assets/30217393-4866-4c4b-913b-dab73707596c)


**Token List**  
![image](https://github.com/user-attachments/assets/f47964c6-eb82-42cc-b480-b3070d4c078b)


**Import Modal**  
![image](https://github.com/user-attachments/assets/1cdddb63-9644-4f04-b4d8-66ca4fe20580)


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
