import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';
import * as fs from 'fs';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser());

  const config = new DocumentBuilder()
    .setTitle('Swagger API')
    .setVersion('1.0')
    .addTag('api')
    .addServer('/')
    .build();
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, documentFactory);

  fs.writeFileSync('swagger-spec.json', JSON.stringify(documentFactory()));
  await app.listen(process.env.PORT ?? 3333);
}
bootstrap();
