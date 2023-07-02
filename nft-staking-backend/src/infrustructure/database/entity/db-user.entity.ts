/* istanbul ignore file */
import { Column, Entity } from 'typeorm';
import { DBBaseEntity } from './db-base.entity';

@Entity({ name: 'users' })
class DBUser extends DBBaseEntity {
    constructor() {
        super();
    }

    @Column({ name: 'roles', type: String, default: null })
    public roles: string[];

    @Column({ name: 'wallet_address', type: String, default: null })
    public walletAddress: string;

    @Column({ name: 'network_name', type: String, default: null })
    public networkName: string;

    @Column({ name: 'is_active', type: Boolean, default: true })
    public isActive: boolean;
}

export default DBUser;
