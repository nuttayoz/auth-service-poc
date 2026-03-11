import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { RequestWithSession } from './session.guard';

export const Session = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext) => {
    const req = ctx.switchToHttp().getRequest<RequestWithSession>();
    return req.session ?? null;
  },
);
