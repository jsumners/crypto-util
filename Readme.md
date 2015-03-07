# Crypto Util

This library provides a set of classes that make using Java's crypto
library easy. This library was written because the author got fed up with
writing variations of the same code whenever he needed to deal with
encryption.

**Note:** this library is developed against Java 1.8.

## Example

Let's assume you need to encrypt the string "foobar" according to
[AES][aes] using the mode "AES/CBC/PKCS5Padding". Then the following
will get you sorted:

```java
Key key = new SecretKeySpec("1234567890123456".getBytes(), "AES");
AesCryptoTool tool = new AesCryptoTool(key);
Optional<EncryptedData> encryptedOptional =
  tool.encrypt("foobar".getBytes());

encryptedOptional.ifPresent(
  (encryptedData) -> {
    String json = encryptedData.toString();
    System.out.println(json);
  }
);
```

## Install

This library is available as a Maven artifact. Simply add the
dependency:

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<depdendencies>
  <dependency>
    <groupId>com.github.jsumners</groupId>
    <artifactId>crypto-util</artifactId>
    <version>0.1.0</version>
  </dependency>
</dependencies>
```

# License

[MIT License](http://jsumners.mit-license.org/)

[aes]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard