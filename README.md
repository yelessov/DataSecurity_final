# 🛡️ Secure Identity & Blockchain Audit System

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Streamlit](https://img.shields.io/badge/Framework-Streamlit-red)
![Security](https://img.shields.io/badge/Focus-Data%20Security-green)

A comprehensive Data Security application designed to demonstrate the implementation of the **CIA Triad** (Confidentiality, Integrity, Availability) along with Non-Repudiation and Identity Management.

This project simulates a secure enterprise environment where user actions are logged in an immutable **Blockchain Ledger**, secrets are encrypted using **AES-GCM**, and documents are signed using **RSA**.

---

## 📸 Screenshots

| **Secure Login (SHA-256 + Salt)** | **Blockchain Audit Log** |
|:---:|:---:|
| <img src="img/login_screen.png" width="400"> | <img src="img/blockchain_log.png" width="400"> |
| *Identity Management System* | *Tamper-proof Event History* |

| **AES-GCM Encryption** | **Vulnerability Analysis** |
|:---:|:---:|
| <img src="img/aes_encryption.png" width="400"> | <img src="img/hacker_attack.png" width="400"> |
| *Confidentiality for User Secrets* | *Dictionary Attack Simulation* |

---

## ✨ Key Features

### 1. 🔐 Identity Management
* **Salted Hashing:** Passwords are never stored in plain text. We use **SHA-256** combined with a unique random **Salt** per user to prevent Rainbow Table attacks.
* **Authentication:** Secure session management using Streamlit's session state.

### 2. 🛡️ Confidentiality (AES Encryption)
* **Algorithm:** **AES-GCM** (Advanced Encryption Standard in Galois/Counter Mode).
* **Key Derivation:** Encryption keys are derived dynamically from the user's password using **PBKDF2HMAC**. Keys are never stored in the database.
* **Data Protection:** Even if the database is stolen, user secrets remain unreadable without the original password.

### 3. 🔗 Integrity (Blockchain Audit)
* **Immutable Ledger:** Every system event (Login, Register, Error) is recorded as a block.
* **Hash Linking:** Each block contains the SHA-256 hash of the previous block. Modifying an old log entry breaks the chain, alerting administrators immediately.

### 4. ✍️ Non-Repudiation (RSA Signatures)
* **Digital Signatures:** Users can generate **RSA-2048** key pairs.
* **Verification:** Documents signed with a Private Key can be verified by anyone using the Public Key, proving authorship and integrity.

### 5. ☠️ Vulnerability Assessment
* **Attack Simulation:** A built-in "Hacker Dashboard" demonstrates the weakness of simple passwords by performing a real-time **Dictionary Attack**.

---

## 🚀 How to Run Locally

### Prerequisites
* Python 3.8+
* Git

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git](https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git)
    cd YOUR_REPO_NAME
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Generate the Dictionary (Optional for full attack demo):**
    ```bash
    python src/dict_generator.py
    ```

4.  **Run the App:**
    ```bash
    streamlit run app.py
    ```

---

## 🛠️ Tech Stack

* **Language:** Python
* **UI Framework:** Streamlit
* **Cryptography:** `cryptography` library (AES, RSA, KDF)
* **Data Handling:** Pandas (for Log Analysis)

---

## 📚 Theory & Concepts
This project implements core Data Security concepts:
* **Symmetric vs Asymmetric Encryption** (AES vs RSA)
* **Cryptographic Hash Functions** (SHA-256)
* **Salting & Key Stretching**
* **Blockchain Structure** (Hash Pointers)
* **Authentication & Session Management**

---

### Author
**[Your Name]** - Data Security Student
