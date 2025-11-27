output "aws_s3_bucket_static_assets_arn" {
  description = "The ARN of the S3 bucket for static assets"
  value       = aws_s3_bucket.static_assets.arn
  
}