import { AtGuard } from './common/guards/at.guard';
import { ValidationPipe } from '@nestjs/common';
import { NestFactory, Reflector } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
    }),
  );
  /*  Use in App Module instead cuz guard needs DI */
  // const reflector = new Reflector(); 
  // app.useGlobalGuards(new AtGuard(reflector));
  await app.listen(3333);
}
bootstrap();
