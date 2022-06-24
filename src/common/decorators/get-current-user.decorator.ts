import { JwtPayload } from './../../auth/types/jwt-payload.type';
import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const GetCurrentUser = createParamDecorator(
  (
    data: string | undefined,
    context: ExecutionContext,
  ): number | JwtPayload => {
    const request = context.switchToHttp().getRequest();

    if (!data) {
      return request.user;
    }

    return request.user[data];
  },
);
