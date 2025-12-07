import e from 'express';
import { GriffinApiClient } from '@saible/common/apis/griffin';
import { initializeApp } from '@saible/common/firebase/app';
import { GriffinEvent, GriffinEventBody } from '@saible/common/types/griffin';
import { LogAlerter } from '@saible/common/utils/logAlerter';
import { logger } from '@saible/common/utils/logger';

export async function griffinWebhook(req: e.Request, res: e.Response) {
  initializeApp({ withServiceAccount: true });
  const griffinApiClient = new GriffinApiClient();
  async function getEvent() {
    const eventUrl = req.body['event-url'];
    if (!eventUrl) {
      return null;
    }
    try {
      return await griffinApiClient.getEvent(eventUrl);
    } catch (error) {
      logger.error(error);
      return null;
    }
  }

  const headers = { ...req.headers };
  if (
    !(await griffinApiClient.verifyIncomingMessage({
      method: req.method,
      authority: req.host,
      body: JSON.stringify(req.body),
      path: '/requests/griffinWebhook',
      headers,
    }))
  ) {
    // If the verification fails for any reason, don't be helpful. Log the failure
    // as a potential security error, and return a 404.
    LogAlerter.securityError('Griffin event verification failure', req.body);
    const event = await getEvent();
    if (event) {
      LogAlerter.securityError('Corresponding Griffin event', event);
    }

    res.sendStatus(404);
    return;
  }

  // From Griffin's Best Practices documentation
  // (https://docs.griffin.com/docs/guides/validate-event-notifications#best-practices),
  // the handler should return a 2xx status quickly and process the event asynchronously.
  // The event will be processed by a Firestore trigger.
  const eventBody: GriffinEventBody = req.body;
  const griffinEvent = GriffinEvent.fromEventBody(eventBody);
  await griffinEvent.writeToFirestore();
  res.status(200).send();
}
