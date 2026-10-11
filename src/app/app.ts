import { JsonPipe } from '@angular/common';
import { HttpClient } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

interface Link {
  id: string;
  href: string;
}

interface Capture {
  id: string;
  xsrf: string | null;
  cookie: string | null;
}

interface Results {
  victim: Capture[];
  attacker: Capture[];
}

@Component({
  selector: 'app-root',
  imports: [JsonPipe],
  templateUrl: './app.html',
  styleUrl: './app.css',
})
export class App {
  private readonly http = inject(HttpClient);

  readonly status = signal('Ready');
  readonly links = signal<Link[]>([]);
  readonly results = signal<Results | null>(null);

  async run(): Promise<void> {
    this.status.set('Running');
    this.results.set(null);

    try {
      await firstValueFrom(this.http.get('/api/session'));
      await firstValueFrom(this.http.post('/api/reset', {}));
      const links = await firstValueFrom(this.http.get<Link[]>('/api/links'));
      this.links.set(links);

      for (const link of links) {
        await firstValueFrom(this.http.post(link.href, { source: 'attacker-controlled-href' }));
      }

      this.results.set(await firstValueFrom(this.http.get<Results>('/api/results')));
      this.status.set('Done');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.status.set(`Error: ${message}`);
    }
  }
}
