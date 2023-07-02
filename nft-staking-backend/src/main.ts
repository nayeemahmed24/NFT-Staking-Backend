import { NestFactory } from '@nestjs/core';
import { AppModule } from './application/modules/app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: (origin, callback) => {
        if (
            origin &&
            (origin.includes('localhost'))
        ) {
            callback(null, true);
        } else {
            callback(null, true);
        }
    },
    credentials: true,
});
  await app.listen(5000);
}
bootstrap();
