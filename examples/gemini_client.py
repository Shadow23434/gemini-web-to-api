from google import genai
from google.genai import types

client = genai.Client(
    api_key="not-needed",
    http_options={
        "base_url": "http://localhost:4981/gemini",
        "api_version": "v1beta"
    }
)

response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents="Hello?"
)

print(response.text)
