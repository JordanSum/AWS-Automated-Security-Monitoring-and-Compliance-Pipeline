variable "bucket_name" {
    description = "The name of the S3 bucket to store static assets."
    type        = string
}

variable "secret_name" {
  description = "Name of the security secret."
  type        = string
}