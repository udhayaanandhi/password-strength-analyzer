# ShieldCheck | Advanced Password Analyzer

ShieldCheck is a modern, premium web application built with **Flask (Python)** that evaluates the strength of user-entered passwords. It is designed to teach password security and basic cryptography concepts by analyzing passwords across multiple vectors and providing immediate feedback.

## ✨ Features

- **Comprehensive Complexity Checks**: Evaluates your password for length, uppercase/lowercase usage, numbers, and special characters.
- **Pattern Recognition**: Automatically detects sequential keystroke patterns (e.g., `1234`, `qwerty`) and penalizes repeating consecutive characters.
- **Data Breach Validation**: Securely integrates with the Have I Been Pwned API (using k-Anonymity SHA-1 hash prefixes) to warn you if your password has been exposed in a known data breach.
- **Strong Password Generation**: Suggests cryptographically secure alternatives if a weak password is provided.
- **Password History Prevention**: Uses a local SQLite database to natively store salted hashes of your passwords and actively warns you if you attempt to reuse an old password.
- **Dynamic Premium UI**: Features a beautiful "glassmorphism" aesthetic with animated pastel gradient backgrounds and responsive interactions (including an eye-icon toggle to securely view the typed password).

## 🚀 Getting Started

### Prerequisites

Ensure you have Python 3.x installed on your operating system.

### Installation

1. Navigate to the project directory in your terminal:
   ```bash
   cd "path/to/task 1"
   ```

2. (Optional but recommended) Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install Flask
   ```
   *(Note: Core features like `hashlib`, `urllib`, and `secrets` utilize Python's standard library and require no external installations.)*

### Running the Application

Start the Flask development server by running:
```bash
python app.py
```

The application will start on `http://127.0.0.1:5000/`. Open this URL in your browser to access the Password Analyzer!

## 📁 Project Structure

- `app.py`: The main Flask routing server and SQLite database handler.
- `analyzer.py`: The core algorithm containing the password entropy math, API checks, pattern constraints, and secure generators. 
- `templates/index.html`: The frontend layout heavily stylized with modern CSS, Bootstrap 5, and JavaScript for user interactivity.

## 🔒 Educational Note
This project was developed specifically to highlight essential practices in modern web security and safe cryptography implementations!
