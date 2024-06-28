#!/bin/bash

# Your OpenAI API key
API_KEY="your_openai_api_key_here"

# API endpoint for chat models
API_URL="https://api.openai.com/v1/chat/completions"

# Check if jq is installed
if ! command -v jq &> /dev/null
then
    echo "Error: jq is not installed. Please install jq to continue."
    exit 1
fi

# Function to make API call
call_gpt() {
  prompt="$1"
  context="You are an expert in cybersecurity, specializing in Kali Linux tools and techniques. Provide short, informative, and precise responses like a professional. Here's the issue: $prompt"
  response=$(curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -d '{
      "model": "gpt-4",
      "messages": [{"role": "system", "content": "You are an expert in cybersecurity, specializing in Kali Linux tools and techniques. Provide short, informative, and precise responses like a professional."},
                   {"role": "user", "content": "'"$context"'"}],
      "max_tokens": 150,
      "temperature": 0.7,
      "top_p": 1.0,
      "n": 1,
      "stop": ["You:", "Pr0x-4o:"]
    }')

  # Check for curl or API errors
  if [ $? -ne 0 ]; then
    echo "Error: Failed to connect to the API."
    exit 1
  fi

  # Parse the response using jq
  gpt_response=$(echo "$response" | jq -r '.choices[0].message.content')

  # Check for jq errors or empty responses
  if [ $? -ne 0 ] || [ -z "$gpt_response" ]; then
    echo "Error: Failed to parse the response or the response is empty."
    exit 1
  fi

  echo "$gpt_response"
}

# Function to print text with typewriter effect
typewriter() {
  text="$1"
  for ((i=0; i<${#text}; i++)); do
    echo -n "${text:$i:1}"
    sleep 0.05
  done
  echo ""
}

# ASCII art header
clear
cat << "EOF"
#1 Ultimate Ethical Hacking Tool
============================================                                  
                       $$$$$$\              
                      $$$ __$$\             
   $$$$$$\   $$$$$$\  $$$$\ $$ |$$\   $$\   
  $$  __$$\ $$  __$$\ $$\$$\$$ |\$$\ $$  |  
  $$ /  $$ |$$ |  \__|$$ \$$$$ | \$$$$  /   
  $$ |  $$ |$$ |      $$ |\$$$ | $$  $$<    
  $$$$$$$  |$$ |      \$$$$$$  /$$  /\$$\   
  $$  ____/ \__|       \______/ \__/  \__|  
  $$ |                                      
  $$ |                                      
  \__|                                      
                                            
      The Tool Made by: pr0x :)         
============================================

Hit Enter to start the bot
EOF

read -r

# Main chat loop
while true; do
  # User input
  echo -e "\033[1mYou:\033[0m "
  read -r user_input

  # Add spacing
  echo ""

  # Format user input
  formatted_input="You: $user_input\nPr0x-4o:"

  # Get GPT response
  gpt_response=$(call_gpt "$formatted_input")

  # Display response with typewriter effect and spacing
  echo -e "\033[1mPr0x-4o:\033[0m "
  typewriter "$gpt_response"
  echo ""
done
