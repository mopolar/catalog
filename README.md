# Item Catalog Project
An Udacity Full Stack Web Developer Nanodegree project developed by Mohammed Gamal.

## About
This application provides a list of football leagues and its clubs beside provide a user registration and authentication system. Only registered users will have the ability to add, edit, and delete.

### Features
- Proper authentication and authorisation check.
- Full CRUD support using SQLAlchemy and Flask.
- JSON endpoints.
- Implements oAuth using Google Sign-in API.

### Project Structure
```
.
├── app.py
├── client_secrets.json
├── database_setup.py
├── README.md
├── static
│   └── style.css
└── templates
    ├──  includes
    │    └── _navbar.html
    ├── all_items.html
    ├── categories.html
    ├── delete_category.html
    ├── delete_item.html
    ├── edit_category.html
    ├── edit_item.html
    ├── home_page.html
    ├── layout.html
    ├── login.html
    ├── new_category.html
    ├── new_item.html
    └── view_item.html
```

## Steps to run this project

1. Download and install [Vagrant](https://www.vagrantup.com/downloads.html).

2. Download and install [VirtualBox](https://www.virtualbox.org/wiki/Downloads).

3. Clone or download the Vagrant VM configuration file from [here](https://github.com/udacity/fullstack-nanodegree-vm).

4. Open the above directory and navigate to the `vagrant/` sub-directory.

5. Open terminal, and type
   ```bash
   vagrant up
   ```
   
6. After the above command succeeds, connect to the newly created VM:
   ```bash
   vagrant ssh
   ```
   
8. Type `cd /vagrant` to navigate to the shared repository.

9. Download or clone this repository, and navigate to it.

11. Install or upgrade Flask:
    ```bash
    pip install --upgrade flask
    ```
12. Set up the database:
    ```bash
    python database_setup.py
    ```

13. Run this application:
    ```bash
    python3 app.py
    ```
14. Open `http://localhost:5000/` in your favourite Web browser.