import { Global, Module } from '@nestjs/common';
import { LoggerProvider } from 'src/domain/logger/logger.provider';
import { StakingLogger } from 'src/domain/logger/staking.logger';

@Global()
@Module({
    imports: [],
    exports: [StakingLogger, LoggerProvider],
    providers: [StakingLogger, LoggerProvider],
})
export class LoggerModule {}