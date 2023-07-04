<#
Script: Commit and Push Changes to GitHub
Author: Jan M. Báez
Email: janmanuelbaez@gmail.com
#>

# Stage the changes
git add .

# Prompt for a commit message
$comment = Read-Host -Prompt 'Enter a commit message'

# Commit the changes with the provided message
git commit -m $comment

# Push the committed changes to the remote repository
git push https://github.com/shyhotboy01/osinator

# Note: Replace 'origin' with the appropriate remote name if necessary.

# Additional Instructions:
# - Ensure you have the necessary permissions to push changes to the repository.
# - Make sure the repository URL is correct. If needed, set the remote URL using the following command:
#   git remote set-url origin git@github.com:shyhotboy01/collector.git

# For more information on using Git and GitHub, refer to the GitHub Docs or Git documentation.
