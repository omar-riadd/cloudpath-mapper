"""Resource collectors (IAM, S3, EC2, ...)."""

from cloud_path_mapper.collectors.ec2_collector import RegionCollector
from cloud_path_mapper.collectors.iam_collector import IAMCollector
from cloud_path_mapper.collectors.s3_collector import S3Collector

__all__ = ["IAMCollector", "RegionCollector", "S3Collector"]
