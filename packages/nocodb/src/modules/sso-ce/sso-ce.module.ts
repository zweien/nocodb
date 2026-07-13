import { Module } from '@nestjs/common';
import { NocoModule } from '~/modules/noco.module';
import { SsoCeController } from './sso-ce.controller';
import { OidcClient } from './oidc.client';

@Module({
  imports: [NocoModule],
  controllers: [SsoCeController],
  providers: [OidcClient],
  exports: [OidcClient],
})
export class SsoCeModule {}
