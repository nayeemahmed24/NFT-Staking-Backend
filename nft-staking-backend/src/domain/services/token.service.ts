import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { TokenDto } from '../dtos/token.dto';
import { ConfigService } from '@nestjs/config';
import DBToken from 'src/infrustructure/database/entity/db-token.entity';
import { UpdateResult, DeleteResult, Repository } from 'typeorm';
import { StakingLogger } from '../logger/staking.logger';

@Injectable()
export class TokenService {
    constructor(
        @InjectRepository(DBToken) private tokenRepository: Repository<DBToken>,
        private readonly configService: ConfigService,
        private readonly logger: StakingLogger,
    ) {}

    async getToken(
        walletAddress: string,
        refreshToken: string,
    ): Promise<DBToken> {
        return await this.tokenRepository.findOne({
            where: { publicAddress: walletAddress, refreshToken: refreshToken },
        });
    }

    async getTokens(walletAddress: string): Promise<DBToken[]> {
        return await this.tokenRepository.find({
            where: { publicAddress: walletAddress },
        });
    }

    public async create(tokenDto: TokenDto): Promise<DBToken> {
        const existingTokens: DBToken[] = await this.tokenRepository.find({
            where: {
                publicAddress: tokenDto.publicAddress,
            },
        });
        const refreshTokenLimit = this.configService.get<number>(
            'PER_USER_REFRESH_TOKEN_LIMIT',
        );

        if (refreshTokenLimit !== null && refreshTokenLimit !== undefined) {
            if (refreshTokenLimit <= existingTokens.length) {
                return null;
            }
        }
        const now: Date = new Date();
        const token = new DBToken();
        token.publicAddress = tokenDto.publicAddress;
        token.refreshToken = tokenDto.refreshToken;
        token.lastUpdateDate = now.toUTCString();
        return await this.tokenRepository.save(token);
    }

    public async update(
        tokenDto: TokenDto,
        oldRefreshToken: string,
    ): Promise<UpdateResult> {
        const existingToken: DBToken = await this.tokenRepository.findOne({
            where: {
                publicAddress: tokenDto.publicAddress,
                refreshToken: oldRefreshToken,
            },
        });
        if (existingToken) {
            const now: Date = new Date();
            existingToken.refreshToken = tokenDto.refreshToken;
            existingToken.lastUpdateDate = now.toUTCString();
            return await this.tokenRepository.update(
                existingToken.id,
                existingToken,
            );
        }
        return null;
    }

    public async delete(
        correlationId: string,
        walletAddress: string,
        refreshToken: string,
    ): Promise<DeleteResult> {
        const token = await this.getToken(walletAddress, refreshToken);
        if (token === null || token === undefined) {
            this.logger.error(
                correlationId,
                'Refresh Token is not found in DB.',
            );
            throw new BadRequestException('Refresh Token is not found in DB.');
        }
        return await this.tokenRepository.delete(token.id);
    }

    public async deleteAll(walletAddress: string) {
        const tokens = await this.getTokens(walletAddress);
        for (const token of tokens) {
            await this.tokenRepository.delete(token.id);
        }
    }
}
