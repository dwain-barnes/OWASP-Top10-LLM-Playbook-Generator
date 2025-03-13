# OWASP LLM Playbook Generator

An interactive web application that generates comprehensive security playbooks for mitigating the OWASP Top 10 vulnerabilities specific to Large Language Model (LLM) applications. The application consists of a Flask backend that leverages the OpenAI API to generate detailed playbooks, paired with a simple HTML/JavaScript frontend.

## Features

- Interactive dropdown to select from the OWASP Top 10 for LLM Applications 2025
- **Web search integration** to fetch the latest OWASP information for accurate content generation using Openai API
- AI-powered generation of detailed security playbooks
- Comprehensive mitigation strategies with technical details
- Code examples for implementation where applicable
- Testing methodologies to verify protections
- Markdown rendering for well-formatted output
- **Caching system** to avoid regenerating the same playbooks repeatedly
- **Export capabilities** to download playbooks as Markdown or PDF files
- **OWASP documentation integration** with direct links to official resources
- Contextual information to help the LLM generate more accurate playbooks
- Sources tracking that displays which references were used during content generation

## Prerequisites

- Python 3.11 or higher
- OpenAI API key

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/dwain-barnes/OWASP-Top10-LLM-Playbook-Generator 
   cd OWASP-Top10-LLM-Playbook-Generator 
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Set up your OpenAI API key:
   ```
   # Linux/macOS
   export OPENAI_API_KEY=your_api_key_here
   
   # Windows (Command Prompt)
   set OPENAI_API_KEY=your_api_key_here
   
   # Windows (PowerShell)
   $env:OPENAI_API_KEY="your_api_key_here"
   ```
   
   Alternatively, you can create a `.env` file in the project root directory:
   ```
   cp .env.template .env
   ```
   Then edit the `.env` file to add your OpenAI API key.

6. Create a cache directory (will be auto-created if missing):
   ```
   mkdir cache
   ```

## Usage

1. Start the Flask server:
   ```
   python app.py
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:5000
   ```

3. Use the dropdown to select a vulnerability from the OWASP Top 10 for LLM Applications 2025.

4. Click the "Generate Playbook" button to generate a comprehensive security playbook.

5. Review the generated playbook for mitigation strategies and implementation details.

6. Export the playbook:
   - Click "Export as Markdown" to download a markdown file


7. View OWASP context and links to official documentation for each vulnerability.

### Caching System

The application includes a file-based caching system that:

- Stores generated playbooks for 7 days
- Avoids unnecessary API calls for previously generated content
- Displays a timestamp for cached content
- Automatically regenerates expired content

To clear the cache, simply delete the files in the `cache` directory.

## Customization

You can customize various aspects of the application:

- Modify the prompt in the `generate_playbook` function in `app.py` to change the structure or content of the generated playbooks.
- Adjust the OpenAI model parameters like `temperature` to control the output style.
- Update the CSS in `index.html` to change the application's appearance.

## Security Considerations

- This application is designed for educational and informational purposes.
- Always review and validate AI-generated security recommendations before implementation.
- Never expose your OpenAI API key in client-side code or public repositories.
- In a production environment, implement proper authentication and rate limiting.

## License

[MIT License](LICENSE)

## Acknowledgments

- [OWASP Top 10 for Large Language Model Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)


