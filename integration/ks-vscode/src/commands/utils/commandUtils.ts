import { window } from 'vscode';
import { logger } from '../../utils/logger';
import { KEEPER_FIELD_TYPES } from '../../utils/constants';

export class CommandUtils {
  static async getSecretNameFromUser(parentFnName: string): Promise<string> {
    logger.logDebug(
      `Getting secret name from user ${parentFnName && `for: ${parentFnName}`}`
    );
    const secretName = await window.showInputBox({
      prompt: 'What do you want to call this record?',
      ignoreFocusOut: true,
      placeHolder: "Enter a name for this record. e.g. 'My Password'",
    });

    if (!secretName) {
      logger.logDebug('No secret name provided by user');
      throw new Error('No record name provided.');
    }

    logger.logDebug(`User provided secret name: ${secretName}`);
    return secretName;
  }

  static async getSecretFieldNameFromUser(
    parentFnName: string
  ): Promise<string> {
    logger.logDebug(`Getting secret field name from user for: ${parentFnName}`);
    const secretFieldName = await window.showInputBox({
      prompt: 'What do you want to call this record field?',
      ignoreFocusOut: true,
      placeHolder: "Enter a name for field. e.g. 'password'",
    });

    if (!secretFieldName) {
      logger.logDebug('No secret field name provided by user');
      throw new Error('No record field name provided.');
    }

    logger.logDebug(`User provided secret field name: ${secretFieldName}`);
    return secretFieldName;
  }

  static getFieldType(fieldName: string): string {
    logger.logDebug(`Determining field type for: ${fieldName}`);
    const patterns = {
      [KEEPER_FIELD_TYPES.SECRET]:
        /(password|secret|key|token|api[_-]?key|private[_-]?key|auth[_-]?token|access[_-]?token|bearer[_-]?token|jwt|session[_-]?id|session[_-]?token|refresh[_-]?token|client[_-]?secret|client[_-]?id|consumer[_-]?key|consumer[_-]?secret|oauth[_-]?token|oauth[_-]?secret|webhook[_-]?secret|signing[_-]?key|encryption[_-]?key|decryption[_-]?key|master[_-]?key|root[_-]?key|private[_-]?key|public[_-]?key|ssh[_-]?key|gpg[_-]?key|certificate|cert|pem|p12|pfx|keystore|truststore|pin|pincode|passcode|passphrase|seed|mnemonic|backup[_-]?code|recovery[_-]?code|totp[_-]?secret|2fa[_-]?secret|mfa[_-]?secret|authenticator[_-]?secret|verification[_-]?code|activation[_-]?code|license[_-]?key|product[_-]?key|serial[_-]?number|api[_-]?secret|webhook[_-]?key|signature|hash|checksum|md5|sha1|sha256|sha512|bcrypt|salt|nonce|iv|vector|credential|cred|auth[_-]?code|authorization[_-]?code|consent[_-]?token|identity[_-]?token|saml[_-]?token|openid[_-]?token|oidc[_-]?token|federation[_-]?token|sso[_-]?token|ldap[_-]?password|ad[_-]?password|domain[_-]?password|service[_-]?account[_-]?key|service[_-]?key|app[_-]?key|app[_-]?secret|application[_-]?key|application[_-]?secret|bot[_-]?token|webhook[_-]?url|callback[_-]?url|redirect[_-]?uri|client[_-]?certificate|server[_-]?certificate|ca[_-]?certificate|intermediate[_-]?certificate|chain[_-]?certificate|fullchain[_-]?certificate|private[_-]?certificate|public[_-]?certificate|ssl[_-]?certificate|tls[_-]?certificate|wildcard[_-]?certificate|domain[_-]?certificate|subdomain[_-]?certificate|wildcard[_-]?key|domain[_-]?key|subdomain[_-]?key|wildcard[_-]?secret|domain[_-]?secret|subdomain[_-]?secret|wildcard[_-]?token|domain[_-]?token|subdomain[_-]?token|wildcard[_-]?password|domain[_-]?password|subdomain[_-]?password|wildcard[_-]?credential|domain[_-]?credential|subdomain[_-]?credential|wildcard[_-]?auth|domain[_-]?auth|subdomain[_-]?auth|wildcard[_-]?key|domain[_-]?key|subdomain[_-]?key|wildcard[_-]?secret|domain[_-]?secret|subdomain[_-]?secret|wildcard[_-]?token|domain[_-]?token|subdomain[_-]?token|wildcard[_-]?password|domain[_-]?password|subdomain[_-]?password|wildcard[_-]?credential|domain[_-]?credential|subdomain[_-]?credential|wildcard[_-]?auth|domain[_-]?auth|subdomain[_-]?auth)/i,
    };

    for (const [type, pattern] of Object.entries(patterns)) {
      if (pattern.test(fieldName)) {
        logger.logDebug(`Field "${fieldName}" matched type: ${type}`);
        return type;
      }
    }

    logger.logDebug(
      `Field "${fieldName}" defaulting to type: ${KEEPER_FIELD_TYPES.TEXT}`
    );
    return KEEPER_FIELD_TYPES.TEXT;
  }
}
