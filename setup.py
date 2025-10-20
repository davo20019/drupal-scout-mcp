from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="drupal-scout-mcp",
    version="0.1.0",
    author="David Loor",
    description="MCP server for discovering Drupal module functionality",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/davo20019/drupal-scout-mcp",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    install_requires=[
        "fastmcp>=0.2.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "drupal-scout=server:main",
        ],
    },
)
