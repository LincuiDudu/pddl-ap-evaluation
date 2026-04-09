from setuptools import setup, find_packages

setup(
    name="cve2pddlap",
    version="0.1.0",
    description="Automated CVE-to-PDDL attack path generation via LLMs",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=[
        "jinja2>=3.1",
        "openai>=1.0",
        "anthropic>=0.80",
        "google-genai>=1.0",
        "tenacity>=8.0",
        "pydantic>=2.0",
        "tqdm>=4.60",
        "python-dotenv>=1.0",
        "tarski",
    ],
)
