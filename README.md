# Promptski 🪄

_Make your prompt shine — with a little Polish flair._

Promptski is a simple web application that helps users refine their prompts for large language models (LLMs) like GPT.

## Features (MVP)

*   Input a rough prompt via a textarea.
*   Receive a polished, improved prompt.
*   (Optional) Get an explanation of the changes made.
*   Copy the polished prompt to the clipboard.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd promptski
    ```
2.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Set up environment variables:**
    Create a `.env` file in the root directory and add your OpenAI API key:
    ```
    OPENAI_API_KEY='your_openai_api_key_here'
    ```
5.  **Run the Flask app:**
    ```bash
    flask run
    ```
    Or:
    ```bash
    python app.py
    ```
    The application will be available at `http://127.0.0.1:5000`.

## Tech Stack

*   **Backend:** Flask (Python)
*   **Frontend:** HTML, CSS, basic JavaScript
*   **LLM Integration:** OpenAI API (GPT-4-turbo planned)
*   **Deployment:** (To be determined - e.g., Render, Railway, Fly.io)
