/* istanbul ignore file */
import { Column, Entity } from 'typeorm';
import { DBBaseEntity } from './db-base.entity';

@Entity({ name: 'tokens' })
class DBToken extends DBBaseEntity {
    constructor() {
        super();
    }
    @Column({ name: 'public_address', type: String, default: null })
    public publicAddress: string;

    @Column({ name: 'refresh_token', type: String, default: null })
    public refreshToken: string;
}

export default DBToken;
