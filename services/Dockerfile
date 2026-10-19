# A single Dockerfile for all KeyMesh services
# Build is performed with the parameter: --build-arg SERVICE=<service_name>

FROM python:3.12-slim

# Name of the service that Docker should copy into the image
ARG SERVICE

# Create a non-root user to enhance container security
RUN useradd --create-home --uid 10001 app

# Main working directory inside the container
WORKDIR /srv

# Copy the KeyMesh shared library
COPY libs/keymesh_common /tmp/keymesh_common

# Copy common Python dependencies
COPY services/requirements.txt .

# Install project dependencies and the shared KeyMesh library
RUN pip install --no-cache-dir -r requirements.txt /tmp/keymesh_common && rm -rf / tmp/keymesh_common

# Copy only the selected service into the container
COPY services/${SERVICE}/app ./app

# Run the service as a non-root user
USER app

# All services will listen on port 8000
EXPOSE 8000

# Launching a FastAPI service using Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0","--port", "8000"]