import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { DeleteResult, Repository, UpdateResult } from 'typeorm';
import { UserDto } from '../dtos/user.dto';
import DBUser from 'src/infrustructure/database/entity/db-user.entity';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(DBUser) private userRepository: Repository<DBUser>,
    ) {}

    async findAll(): Promise<DBUser[]> {
        return await this.userRepository.find();
    }

    async getUser(walletAddress: string): Promise<DBUser> {
        return await this.userRepository.findOne({
            where: { walletAddress: walletAddress },
        });
    }

    public async createOrUpdate(userDto: UserDto): Promise<DBUser> {
        const now: Date = new Date();
        const user = new DBUser();
        user.walletAddress = userDto.publicAddress;
        user.networkName = userDto.networkName;
        user.lastUpdateDate = now.toUTCString();

        // eslint-disable-next-line prefer-const
        let existingUser: DBUser = await this.userRepository.findOne({
            where: {
                walletAddress: userDto.publicAddress,
            },
        });

        if (existingUser == null || existingUser == undefined) {
            return await this.userRepository.save(user);
        } else {
            existingUser.lastUpdateDate = now.toUTCString();
            await this.userRepository.update(existingUser.id, existingUser);
            return existingUser;
        }
    }

    public async updateLastLoginDate(
        publicAddress: string,
    ): Promise<UpdateResult> {
        const existingUser: DBUser = await this.userRepository.findOne({
            where: {
                walletAddress: publicAddress,
            },
        });
        if (existingUser !== null && existingUser !== undefined) {
            const today: Date = new Date();
            existingUser.lastUpdateDate = today.toUTCString();
            return await this.userRepository.update(
                existingUser.id,
                existingUser,
            );
        }
        return null;
    }

    public async update(user: DBUser): Promise<UpdateResult> {
        const today: Date = new Date();
        user.lastUpdateDate = today.toUTCString();
        return await this.userRepository.update(user.id, user);
    }

    public async delete(id): Promise<DeleteResult> {
        return await this.userRepository.delete(id);
    }
}
