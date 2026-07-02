#!/bin/bash
# Setup script for Streamlit Cloud deployment
# Downloads required spaCy model before app starts

echo "🚀 Downloading spaCy English model..."
python -m spacy download en_core_web_sm

echo "✅ Setup complete!"
