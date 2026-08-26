import "reflect-metadata";
import { ValidationPipe } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { SafeExceptionFilter } from "./api/safe-exception.filter";

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.useGlobalFilters(new SafeExceptionFilter());
  app.enableCors({ origin: process.env.WEB_ORIGIN ?? "http://localhost:3000" });
  await app.listen(Number(process.env.PORT ?? 8080), "0.0.0.0");
}

void bootstrap();
