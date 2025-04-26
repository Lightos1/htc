# Base64 encoded string (input)
$base64String = "aiSYai+t/RqkuNSQdKp5d7nBmbSV3vovjq0TUbiXa2c="

# Decode the Base64 string into bytes
$decodedBytes = [Convert]::FromBase64String($base64String)

# Extract the first 16 bytes (IV)
$iv = $decodedBytes[0..15]

# Convert the IV bytes to hexadecimal format and join them into a single string
$hexIv = ($iv | ForEach-Object { $_.ToString("X2") }) -join ""

# Print the IV in hexadecimal format
Write-Host "IV (in hex): $hexIv"
