import os
import json
import time
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, request, send_file, Response
from flask_cors import CORS
import requests

import markdown
from dotenv import load_dotenv
from openai import OpenAI

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
# Enable CORS to allow requests from the frontend
CORS(app)

# Create cache directory if it doesn't exist
CACHE_DIR = Path("cache")
CACHE_DIR.mkdir(exist_ok=True)

# OWASP documentation and references
OWASP_DOCS = {
    "LLM01:2025 Prompt Injection": {
        "description": "Occurs when an attacker manipulates an LLM through carefully crafted prompts to cause unintended behavior or outputs.",
        "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "examples": [
            "Direct prompt injection (e.g., jailbreaking attempts)",
            "Indirect prompt injection via manipulated external data",
            "Multimodal injection with hidden instructions (e.g., in images)",
            "Multilingual/Obfuscated Attack"
        ]
    },
    "LLM02:2025 Sensitive Information Disclosure": {
        "description": "Occurs when an LLM inadvertently reveals private data, secrets, or sensitive information that should remain confidential.",
        "url": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/",
        "examples": [
            "Unintentional Data Exposure",
            "Targeted Prompt Injection",
            "Data Leak via Training Data"
        ]
    },

    "LLM03:2025 Supply Chain": {
        "description": "Risks introduced through dependencies, pre-trained models, or third-party components used in the LLM application pipeline.",
        "url": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
        "examples": [
            "Vulnerable Python Library",
            "Direct Tampering",
            "Finetuning Popular Model"
        ]
    },
        "LLM04:2025 Data and Model Poisoning": {
        "description": "Involves the manipulation of training data or fine-tuning processes to introduce vulnerabilities, biases, or backdoors into the model.",
        "url": "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/",
        "examples": [
            "Injecting malicious data into training sets",
            "Backdoor attacks through manipulated fine-tuning",
            "Bias injection that alters model behavior"
        ]
    },
    "LLM05:2025 Improper Output Handling": {
        "description": "Occurs when LLM-generated outputs are not properly validated, sanitized, or handled before being passed on to other components.",
        "url": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/",
        "examples": [
            "XSS via unsanitized outputs",
            "SQL injection through LLM-generated queries",
            "Command injection leading to remote code execution"
        ]
    },
    "LLM06:2025 Excessive Agency": {
        "description": "When LLMs are granted too much autonomy or authority, enabling them to take actions without proper human oversight or necessary restrictions.",
        "url": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/",
        "examples": [
            "LLM taking unauthorized actions (e.g., sending emails or modifying data)",
            "Bypassing human-in-the-loop approval processes",
            "Automated decisions that lead to harmful outcomes"
        ]
    },
    "LLM07:2025 System Prompt Leakage": {
        "description": "Occurs when the system prompts or internal instructions that define the LLM's behavior are exposed to unauthorized users.",
        "url": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/",
        "examples": [
            "Leakage of internal system prompts or guardrails",
            "Extraction of confidential business logic from prompt instructions",
            "Unauthorized disclosure of sensitive prompt details"
        ]
    },
    "LLM08:2025 Vector and Embedding Weaknesses": {
        "description": "Vulnerabilities in the vector storage and retrieval systems that support many LLM applications, which can be exploited to manipulate outputs or access sensitive data.",
        "url": "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/",
        "examples": [
            "Data Poisoning",
            "Access control & data leakage risk by combining data with different access restrictions",
            "Behavior alteration of the foundation model"
        ]
    },
     "LLM09:2025 Misinformation": {
        "description": "LLMs generating false, misleading, or harmful information that is presented as factual.",
        "url": "https://owasp.org/www-project-top-10-for-large-language-model-applications/descriptions/Misinformation.html",
        "examples": ["Hallucinations", "Outdated information", "Fabricated references"]
    },
    "LLM10:2025 Unbounded Consumption": {
        "description": "Exploitation of LLM resources leading to excessive usage, escalating costs, or denial of service.",
        "url": "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/",
        "examples": [
            "Denial of Wallet (DoW)",
            "Functional Model Replication",
            "Resource-Intensive Queries"
        ]
    }
}

# Cache management functions
def get_cache_key(vulnerability):
    """Generate a unique cache key for a vulnerability."""
    return hashlib.md5(vulnerability.encode()).hexdigest()

def get_from_cache(vulnerability):
    """Try to retrieve a cached playbook for the given vulnerability."""
    cache_key = get_cache_key(vulnerability)
    cache_file = CACHE_DIR / f"{cache_key}.json"
    
    if cache_file.exists():
        try:
            # Check if cache is less than 7 days old
            file_age = time.time() - cache_file.stat().st_mtime
            if file_age < 7 * 24 * 60 * 60:  # 7 days in seconds
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                    logger.info(f"Cache hit for vulnerability: {vulnerability}")
                    return cache_data
            else:
                logger.info(f"Cache expired for vulnerability: {vulnerability}")
        except Exception as e:
            logger.error(f"Error reading cache: {str(e)}")
    
    logger.info(f"Cache miss for vulnerability: {vulnerability}")
    return None

def save_to_cache(vulnerability, playbook, owasp_context):
    """Save a generated playbook to the cache."""
    cache_key = get_cache_key(vulnerability)
    cache_file = CACHE_DIR / f"{cache_key}.json"
    
    cache_data = {
        "vulnerability": vulnerability,
        "playbook": playbook,
        "owasp_context": owasp_context,
        "timestamp": datetime.now().isoformat(),
    }
    
    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        logger.info(f"Saved to cache: {vulnerability}")
    except Exception as e:
        logger.error(f"Error saving to cache: {str(e)}")

def fetch_owasp_context(vulnerability):
    """Fetch additional context from OWASP for a given vulnerability."""
    # Use predefined context or fetch from URL if needed
    if vulnerability in OWASP_DOCS:
        context = OWASP_DOCS[vulnerability]
        # Try to fetch real-time data for additional context
        try:
            if "url" in context and context["url"]:
                response = requests.get(context["url"], timeout=5)
                if response.status_code == 200:
                    # Extract some content from the page for additional context
                    # This is simplified - in a real app you'd want proper HTML parsing
                    logger.info(f"Successfully fetched additional OWASP data for {vulnerability}")
        except Exception as e:
            logger.warning(f"Could not fetch live OWASP data: {str(e)}")
        
        return context
    else:
        return {
            "description": "No official description available",
            "url": "https://genai.owasp.org/llm-top-10/",
            "examples": []
        }




client = OpenAI(api_key='your key here')


# Define the OWASP Top 10 for LLM Applications 2025
owasp_top_10 = [
    "LLM01:2025 Prompt Injection",
    "LLM02:2025 Sensitive Information Disclosure",
    "LLM03:2025 Supply Chain",
    "LLM04:2025 Data and Model Poisoning",
    "LLM05:2025 Improper Output Handling",
    "LLM06:2025 Excessive Agency",
    "LLM07:2025 System Prompt Leakage",
    "LLM08:2025 Vector and Embedding Weaknesses",
    "LLM09:2025 Misinformation",
    "LLM10:2025 Unbounded Consumption"
]

# Endpoint to provide the list of vulnerabilities to the frontend
@app.route('/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """Return the list of OWASP Top 10 vulnerabilities."""
    return jsonify(owasp_top_10)

# Export endpoints
@app.route('/export_markdown/<vulnerability>', methods=['GET'])
def export_markdown(vulnerability):
    """Export a playbook as a markdown file."""
    if vulnerability not in owasp_top_10:
        return jsonify({"error": "Invalid vulnerability"}), 400
    
    # Try to get from cache first
    cached_data = get_from_cache(vulnerability)
    
    if cached_data:
        playbook_md = cached_data["playbook"]
    else:
        # Generate if not in cache
        try:
            result = generate_playbook_content(vulnerability)
            playbook_md = result["playbook"]
        except Exception as e:
            return jsonify({"error": f"Failed to generate playbook: {str(e)}"}), 500
    
    # Create a response with the markdown content
    response = Response(
        playbook_md,
        mimetype="text/markdown",
        headers={
            "Content-Disposition": f"attachment;filename={vulnerability.replace(' ', '_')}_Playbook.md"
        }
    )
    return response

@app.route('/export_pdf/<vulnerability>', methods=['GET'])
def export_pdf(vulnerability):
    """Export a playbook as a PDF file."""
    if vulnerability not in owasp_top_10:
        return jsonify({"error": "Invalid vulnerability"}), 400
    
    # Try to get from cache first
    cached_data = get_from_cache(vulnerability)
    
    if cached_data:
        playbook_md = cached_data["playbook"]
    else:
        # Generate if not in cache
        try:
            result = generate_playbook_content(vulnerability)
            playbook_md = result["playbook"]
        except Exception as e:
            return jsonify({"error": f"Failed to generate playbook: {str(e)}"}), 500
    
    # Convert markdown to HTML
    html_content = markdown.markdown(playbook_md)
    
    # Add some basic styling
    styled_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{vulnerability} Playbook</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }}
            h1, h2, h3 {{ color: #2c3e50; }}
            code {{ background-color: #f8f8f8; padding: 2px 4px; border-radius: 4px; }}
            pre {{ background-color: #f8f8f8; padding: 10px; border-radius: 4px; overflow-x: auto; }}
            blockquote {{ border-left: 4px solid #ccc; padding-left: 15px; color: #666; }}
            .header {{ margin-bottom: 30px; }}
            .footer {{ margin-top: 30px; font-size: 0.8em; color: #999; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>OWASP Top 10 for LLM Applications 2025</h1>
            <h2>{vulnerability} - Security Playbook</h2>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        </div>
        
        {html_content}
        
        <div class="footer">
            <p>This playbook was auto-generated and should be reviewed by security professionals before implementation.</p>
            <p>Source: OWASP Top 10 for LLM Applications 2025</p>
        </div>
    </body>
    </html>
    """

# Helper function to generate playbook content
def generate_playbook_content(vulnerability):
    """Generate a playbook for the selected vulnerability using the new OpenAI API with web search."""
    # Fetch OWASP context for the vulnerability
    owasp_context = fetch_owasp_context(vulnerability)
    
    system_prompt = """You are an expert cybersecurity consultant with deep knowledge of OWASP Top 10 for LLM Applications.
Your task is to create accurate, technically detailed, and actionable security playbooks.
Use the web search capability to find the most up-to-date information about the specified vulnerability from official OWASP sources https://genai.owasp.org/llm-top-10/
Avoid generic advice and include specific implementation details, real code examples, and concrete testing methodologies.
Each playbook should be tightly focused on the specific vulnerability and represent current security best practices."""

    user_prompt = f"""Use web search to find official information about the '{vulnerability}' vulnerability from the OWASP Top 10 for LLM Applications https://genai.owasp.org/llm-top-10/.
    
Then, generate a comprehensive security playbook for mitigating this vulnerability in LLM applications.
                
The playbook must include:
1. An in-depth description of the vulnerability and how it works, based on official OWASP documentation
2. Potential impact and risk assessment if exploited
3. 5-7 specific mitigation strategies with detailed technical implementation steps
4. Working code examples using Python, JavaScript, or other relevant languages
5. Testing methodologies to verify protections are working properly
6. Sample policies and guardrails organizations should implement
7. Additional resources and references from authoritative sources

Format the response in a well-structured, markdown format suitable for developers and security professionals."""
    
    try:
        # Call OpenAI API with web search enabled
        response = client.responses.create(
            model="gpt-4o-mini",  # Use an appropriate model with web search capability
            tools=[{"type": "web_search_preview"}],
            input=[
                {
                    "role": "system", 
                    "content": system_prompt
                },
                {
                    "role": "user", 
                    "content": user_prompt
                }
            ],
            temperature=0.4
        )
        
        # Extract the generated playbook content from the response
        playbook_content = response.output_text
        
        
        # Save to cache
        save_to_cache(vulnerability, playbook_content, owasp_context)
        
        return {
            "playbook": playbook_content,
            "owasp_context": owasp_context
        }
    
    except Exception as e:
        logger.error(f"Error generating playbook: {str(e)}")
        # Just raise the exception without attempting fallback
        raise Exception(f"Failed to generate playbook: {str(e)}")

# Endpoint to generate a playbook for a selected vulnerability
@app.route('/generate_playbook', methods=['POST'])
def generate_playbook():
    """Generate a playbook for the selected vulnerability using OpenAI API or cache."""
    # Parse the incoming JSON request
    data = request.json
    vulnerability = data.get('vulnerability')

    # Validate the selected vulnerability
    if not vulnerability:
        return jsonify({"error": "Missing vulnerability"}), 400
    
    if vulnerability not in owasp_top_10:
        return jsonify({"error": f"Invalid vulnerability: {vulnerability}"}), 400

    # Check if we have this playbook cached
    cached_data = get_from_cache(vulnerability)
    
    if cached_data:
        # Return cached playbook
        return jsonify({
            "playbook": cached_data["playbook"],
            "owasp_context": cached_data["owasp_context"],
            "cached": True,
            "timestamp": cached_data["timestamp"]
        })
    
    # Generate new playbook
    try:
        result = generate_playbook_content(vulnerability)
        
        return jsonify({
            "playbook": result["playbook"],
            "owasp_context": result["owasp_context"],
            "cached": False
        })
    
    except Exception as e:
        logger.error(f"Error generating playbook: {str(e)}")
        return jsonify({"error": f"Failed to generate playbook: {str(e)}"}), 500

# Serve the static frontend files
@app.route('/', methods=['GET'])
def serve_frontend():
    with open('index.html', 'r') as file:
        return file.read()

# Run the Flask app
if __name__ == '__main__':
    print("Starting OWASP LLM Playbook Generator server...")
    print(f"Available vulnerabilities: {', '.join(owasp_top_10)}")
    print("Access the web interface at http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
