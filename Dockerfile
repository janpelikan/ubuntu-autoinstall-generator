FROM alpine:latest AS ubuntu-autoinstall-generator

# Set working directory
WORKDIR /app

# Install required packages
RUN apk add --no-cache bash sed curl gpg xorriso syslinux 7zip

# Copy the custom script to the container
COPY ubuntu-autoinstall-generator.sh /app/ubuntu-autoinstall-generator.sh

# Define the entry point with script arguments
ENTRYPOINT ["bash", "ubuntu-autoinstall-generator.sh"]

# Default command if no arguments provided
CMD ["--help"]
