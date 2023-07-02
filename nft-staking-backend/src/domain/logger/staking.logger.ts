/* istanbul ignore file */
import {
    ConsoleLogger,
    Injectable,
    LoggerService,
    Scope,
} from '@nestjs/common';

import { LoggerProvider } from './logger.provider';

@Injectable({ scope: Scope.TRANSIENT })
export class StakingLogger extends ConsoleLogger implements LoggerService {
    constructor(private readonly loggerProvider: LoggerProvider) {
        super();
        console.log('StakingLogger Initiated.');
    }
    verbose(correlationId: string, message: any) {
        this.loggerProvider.logger.log(
            'verbose',
            StakingLogger.formatLogging(correlationId, message),
        );
    }

    debug(correlationId: string, message: any) {
        this.loggerProvider.logger.log(
            'debug',
            StakingLogger.formatLogging(correlationId, message),
        );
    }

    log(correlationId: any, message: any) {
        this.loggerProvider.logger.log(
            'info',
            StakingLogger.formatLogging(correlationId, message),
        );
    }

    warn(correlationId: string, message: any) {
        this.loggerProvider.logger.log(
            'warn',
            StakingLogger.formatLogging(correlationId, message),
        );
    }

    error(correlationId: string, message: any) {
        this.loggerProvider.logger.log(
            'error',
            StakingLogger.formatLogging(correlationId, message),
        );
    }

    private static formatLogging(correlationId: string, message: any): any {
        return `[CorrelationId] : ${correlationId} -- [Message] : ${message}`;
    }
}
