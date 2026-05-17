import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# Load environment variables
load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")


def explain_vulnerability(text):

    llm = ChatGroq(
    temperature=0.3,
    groq_api_key=GROQ_API_KEY,
    model_name="llama-3.1-8b-instant"
)

    prompt = f"""
    Explain this cybersecurity vulnerability in simple terms.

    Vulnerability:
    {text}

    Include:
    1. What vulnerability it is
    2. Why it is dangerous
    3. Real-world impact
    4. How developers can fix it
    """

    response = llm.invoke(prompt)

    return response.content


if __name__ == "__main__":

    test_vulnerability = """
    Detected path traversal vulnerability using ../ in file path handling.
    """

    result = explain_vulnerability(test_vulnerability)

    print("\nAI Explanation:\n")
    print(result)