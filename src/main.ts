import { NestFactory } from '@nestjs/core';
import { readFileSync } from 'fs';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import * as dotenv from 'dotenv';

dotenv.config();

async function bootstrap() {
  // Sets up HTTPS by reading SSL certificate and key from file system
  const httpsOptions = {
    key: readFileSync(
      './certs/fs.tpommellet.docker.dev-franceconnect.fr-key.pem',
    ),
    cert: readFileSync('./certs/fs.tpommellet.docker.dev-franceconnect.fr.pem'),
  };
  const app = await NestFactory.create(AppModule, { httpsOptions });

  app.use(cookieParser());

  // Listen on port 443, the standard port for HTTPS
  await app.listen(443);
}
bootstrap();
