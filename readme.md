# Block Cipher Cryptography Algorithm Based on Chess Patterns

This project is the result of a thesis titled "**Perancangan Algoritma Kriptografi Block Cipher Berbasis Permainan Pola Catur Sebagai Kunci Dinamis**" ("Design of a Block Cipher Cryptography Algorithm Based on Chess Pattern Game as a Dynamic Key"). It introduces an innovative 64-bit symmetric block cipher algorithm that leverages the dynamic and complex patterns of chess movements to generate cryptographic keys. This approach aims to enhance data security by moving beyond the static key patterns commonly used in traditional cryptographic algorithms.

The core of this research is the development of a novel encryption method that utilizes two distinct keys for its operation:
* **Key 1**: An 8-character ASCII string.
* **Key 2**: A dynamic key derived from the movements of a chess piece throughout a game.

This dual-key system, combined with a series of cryptographic operations, results in a robust and secure encryption algorithm suitable for a variety of real-world applications.

***

## ✨ Features

This project offers a range of features that make it a powerful tool for data encryption and security:

* **Dynamic Key Generation**: Unlike traditional algorithms that rely on static keys, this project uses the movements of a chess piece from a given game to generate a dynamic and unpredictable second key (Key 2). This significantly increases the complexity for potential attackers.

* **Dual-Key System**: The algorithm's security is enhanced by its use of two keys: a user-provided 8-character ASCII string (Key 1) and the chess-based dynamic key (Key 2). This layered approach to keying adds an extra dimension of security.

* **Robust Encryption Methods**: The algorithm employs a combination of well-established cryptographic techniques to ensure a high level of security, including:
    * **Bit Transposition**: An 8x8 matrix is used to shuffle the bits of the plaintext, obfuscating the original data structure.
    * **Bit Substitution**: An S-box is utilized for substituting bit patterns, adding confusion to the encryption process.
    * **XOR Logical Operations**: This fundamental operation is used to combine the plaintext with the keys, a critical step in modern cryptography.
    * **Bit Shifting**: A simple yet effective method of bit transposition is applied by shifting bits to the left or right, further scrambling the data.

* **Proven Security**: The algorithm's effectiveness has been rigorously tested using industry-standard cryptographic analysis techniques:
    * **Pearson Correlation Test**: The results show a very weak correlation between the plaintext and the resulting ciphertext, with the best-case correlation value being as low as **0.00852**. This indicates that the ciphertext bears little to no statistical resemblance to the original message.
    * **Avalanche Effect (AE)**: The algorithm demonstrates a strong Avalanche Effect, with an average value of **49.17%** for a single-character change in the plaintext (an 8-bit change). This is very close to the ideal 50% AE, signifying that small changes in the input produce significant, unpredictable changes in the output.

* **Web-Based Application**: To make the algorithm accessible, a user-friendly web application has been developed. This allows users to easily encrypt and decrypt messages without needing to understand the underlying cryptographic complexities. The application is built with a modern, microservices-based architecture for scalability and maintainability.

***

## 🏗️ System Architecture

The project is designed with a clean and efficient microservices architecture, which separates the core functionalities into distinct services. This modular approach enhances scalability, allows for independent development and deployment of services, and improves the overall resilience of the system.

The architecture consists of three main components:

1.  **API Gateway**: This service acts as the single entry point for all incoming requests. It is responsible for routing requests to the appropriate backend service (either the Encryption Service or the Decryption Service). This simplifies the client-side logic and provides a unified interface to the system.

2.  **Encryption Service**: This service handles all encryption requests. When a user submits a plaintext message and the required keys, the API Gateway forwards the request to this service, which then performs the encryption using the chess-based algorithm and returns the resulting ciphertext.

3.  **Decryption Service**: This service is responsible for decrypting messages. When a user provides a ciphertext and the correct corresponding keys, the API Gateway routes the request here. The service then applies the decryption algorithm to recover the original plaintext.

This separation of concerns ensures that the encryption and decryption processes are handled by dedicated services, making the system more organized and easier to manage.

***

## ⚙️ How the Algorithm Works

The cryptographic algorithm at the heart of this project is a symmetric block cipher, meaning the same keys are used for both encryption and decryption. It operates on 64-bit blocks of data and involves a series of rounds, with the number of rounds dynamically determined by the content of Key 1.

### Key Generation

* **Key 1**: A standard 8-character ASCII string provided by the user.
* **Key 2**: This dynamic key is generated from a chess game. The user selects a specific chess piece from a game (provided in PGN format). The sequence of squares that this piece occupies throughout the game forms the basis of Key 2.

### Encryption Process

The encryption process is a multi-step procedure that applies a series of transformations to the plaintext data in multiple rounds:

1.  **Initialization**: The plaintext is converted into its binary representation. This binary data, along with the binary form of Key 1, is loaded into separate 8x8 matrices. The arrangement of bits within these matrices is shuffled based on the patterns derived from Key 2 (the chess moves).

2.  **Initial Round**: The plaintext and key matrices undergo a transposition process. The resulting bitstreams are then combined using an XOR operation. The outcome of this is then subjected to a bit-shifting operation to produce the ciphertext for the first round.

3.  **Iterative Rounds**: The output of the initial round serves as the input for a series of subsequent rounds. In each of these rounds, the data undergoes substitution using an S-box, another AddChessPattern transposition based on Key 2, an XOR operation with a round-specific key derived from Key 1, and a final bit transposition.

4.  **Final Round**: The last round follows a similar process but omits the AddChessPattern step to produce the final ciphertext block.

This iterative process, combining substitution, permutation, and key mixing, ensures that the relationship between the plaintext and the ciphertext is thoroughly obscured, resulting in a high degree of security.

***

## 🔌 API Documentation

The web application exposes a simple and intuitive API for encrypting and decrypting data. All endpoints are accessed through the API Gateway.

### Encrypt Endpoint

* **URL**: `/encrypt`
* **Method**: `POST`
* **Description**: Encrypts a given plaintext message.
* **Form Data**:
    * `plaintext` (string, required): The message to be encrypted.
    * `key1` (string, required): The 8-character ASCII key.
    * `key2` (string, optional): A comma-separated string of chess moves (e.g., "d8,b8").
    * `square` (string, optional): The initial square of the chess piece (e.g., "d8"). Used in conjunction with `text_pgn`.
    * `text_pgn` (string, optional): The PGN representation of the chess game.
* **Headers**:
    * `X-Encryption-Type` (string, optional): Set to `base64` if the input data is Base64 encoded.
* **Success Response (200 OK)**:
    ```json
    {
      "ciphertext": "5482cea05ad2884b...",
      "encryption time": 0.0045
    }
    ```
* **Error Response**:
    ```json
    {
      "ciphertext": "Error: key1 harus 8 karakter (termasuk spasi)."
    }
    ```

### Decrypt Endpoint

* **URL**: `/decrypt`
* **Method**: `POST`
* **Description**: Decrypts a given ciphertext.
* **Form Data**:
    * `ciphertext` (string, required): The encrypted message.
    * `key1` (string, required): The 8-character ASCII key used for encryption.
    * `key2` (string, optional): The same chess moves used for encryption.
    * `square` (string, optional): The initial square of the chess piece.
    * `text_pgn` (string, optional): The PGN of the chess game.
* **Headers**:
    * `X-Encryption-Type` (string, optional): Set to `base64` if the input is Base64 encoded.
* **Success Response (200 OK)**:
    ```json
    {
      "ciphertext": "5482cea05ad2884b...",
      "decrypted text": "Tekkom unggul, jaya, bermartabat",
      "decryption time": 0.0038
    }
    ```
* **Error Response**:
    ```json
    {
      "decrypted text": "Error: Cipherteks salah, cipherteks yang benar adalah kelipatan 16."
    }
    ```

***

## 🚀 How to Set Up and Run the Project

To get the project up and running on your local machine, follow these steps:

### Prerequisites

* Python 3.8 or higher
* Flask (`pip install Flask`)
* Python-chess (`pip install python-chess`)
* Requests (`pip install requests`)

### Installation and Execution

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/mrizkiw/ciphermate-chess-crypto-algorithm.git
    cd ciphermate-chess-crypto-algorithm
    ```

2.  **Run the Services**: You will need to run each of the three services in separate terminal windows.

    * **Terminal 1: Encryption Service**
        ```bash
        cd encryption_service
        python app.py
        ```
        This will start the Encryption Service on port `5011`.

    * **Terminal 2: Decryption Service**
        ```bash
        cd decryption_service
        python app.py
        ```
        This will start the Decryption Service on port `5012`.

    * **Terminal 3: API Gateway**
        ```bash
        cd api_gateway
        python app.py
        ```
        This will start the API Gateway on port `5050`.

3.  **Test the API**: Once all services are running, you can use the provided `api-test.py` script to verify that everything is working correctly.
    ```bash
    python api-test.py
    ```
    This script will run a series of encryption and decryption tests, including basic encryption, chess-based encryption with PGN, and Base64 encoded encryption. You should see successful status codes and the JSON responses for each test case printed to the console.

By following these steps, you will have a fully functional local instance of the chess-based cryptography application, ready for you to explore and experiment with.

***

## 🧪 API Test Script

A test script (`api-test.py`) is provided to help you verify and demonstrate the API endpoints. This script automatically runs several encryption and decryption scenarios and prints the results to your console.

### How to Run

Make sure all services are running, then execute:

```bash
python api-test.py
```

### Test Scenarios

The script performs several automated tests:

1. **Basic Encrypt & Decrypt**
    - Encrypts a simple message using Key 1 and Key 2.
    - Decrypts the resulting ciphertext using the same keys.

2. **Encrypt & Decrypt with Square & PGN**
    - Encrypts a message using Key 1, an initial square, and a PGN chess game.
    - Decrypts the ciphertext with the same parameters.

3. **Base64 Encrypt & Decrypt**
    - Encrypts the message, Key 1, and Key 2 encoded in Base64.
    - Decrypts the ciphertext using the same parameters and the `X-Encryption-Type: base64` header.

### Example Output

Each test prints the HTTP status and JSON response from the API, for example:

```
--- Basic Encrypt ---
Status: 200
Response: {'ciphertext': '0fad7317a23f7b9a...', 'encryption time': 0.0045}

--- Decrypt ---
Status: 200
Response: {'ciphertext': '0fad7317a23f7b9a...', 'decrypted text': 'I love cryptography. Made with love by Mrizki W.', 'decryption time': 0.0038}
```

### Script Structure

- `test_basic_encrypt()`: Sends a request to `/encrypt` with basic data.
- `test_chess_encrypt()`: Sends a request to `/encrypt` with square and PGN.
- `test_base64_encrypt()`: Sends a request to `/encrypt` with Base64-encoded data.
- `test_decrypt()`: Sends a request to `/decrypt` for each ciphertext.
- `main()`: Runs all the above tests in sequence.

### Customization

You can modify the message, keys, or PGN in the script for further testing.

***

## 🌐 Live Demo

You can also try the live demo at [https://ciphermate.mrizkiw.com](https://ciphermate.mrizkiw.com)
![Demo Screenshot](https://ciphermate.mrizkiw.com/assets/demo-screenshot.jpg)