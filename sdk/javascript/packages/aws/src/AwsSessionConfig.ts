export class AWSSessionConfig {
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
  regionName: string;

  constructor(
    awsAccessKeyId: string,
    awsSecretAccessKey: string,
    regionName: string
  ) {
    this.awsAccessKeyId = awsAccessKeyId;
    this.awsSecretAccessKey = awsSecretAccessKey;
    this.regionName = regionName;
  }
}