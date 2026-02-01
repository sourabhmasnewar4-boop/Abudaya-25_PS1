# Start with a Python 3.9 base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application code (app.py, templates folder, etc.)
COPY . .

# Expose port 5000 to the outside world
EXPOSE 5000

# The command to run your app using the eventlet server
# This is read from your app.py file where socketio.run() is defined
CMD ["python", "app.py"]
